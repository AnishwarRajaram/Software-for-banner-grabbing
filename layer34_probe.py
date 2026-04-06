import sys
from typing import Optional, Dict, Any
from scapy.all import IP, TCP, ICMP, UDP, sr1, send, conf

conf.verb = 0


class RawProbeError(Exception):
    """Raised when a Scapy probe gets no response within the timeout."""
    def __init__(self, probe_name: str, timeout: float):
        super().__init__(f"Probe '{probe_name}' got no response after {timeout}s")
        self.probe_name = probe_name
        self.timeout    = timeout


# ──────────────────────────────────────────────
#  ICMP probe definitions  (layer-3 signals)
#  TCP probes are gone — we reuse the SYN-ACK
#  that port_check already captured for free.
# ──────────────────────────────────────────────

def _probe_icmp_echo(ip: str):
    """
    Standard ICMP Echo with DF=1.  Reply TTL + DF bit corroborate
    what we read from the SYN-ACK.  Fires concurrently with TCP work.
    """
    pkt = IP(dst=ip, flags="DF") / ICMP(type=8, code=0, id=0xBEEF, seq=1)
    return "icmp_echo", pkt


def _probe_icmp_echo_large(ip: str):
    """
    512-byte ICMP Echo.  DF handling on oversized replies differs by stack:
    Linux keeps DF=1, some Windows builds clear it.
    """
    pkt = IP(dst=ip) / ICMP(type=8, code=0, id=0xBEEF, seq=2) / (b"X" * 512)
    return "icmp_echo_large", pkt


def _probe_icmp_unreach(ip: str):
    """
    UDP to closed traceroute port — elicits ICMP type-3 Unreachable.
    quote_len distinguishes stacks: Linux ≈ 28 bytes, Windows up to 576.
    Also gives a second independent TTL sample.
    """
    pkt = IP(dst=ip, ttl=64) / UDP(dport=33434, sport=54321) / (b"Z" * 8)
    return "icmp_unreach", pkt



class Layer34Prober:
    """
    Combined layer-3/4 fingerprinting module.

    Design
    ------
    Layer-4 (TCP stack) data comes from the SYN-ACK that port_check.py
    already captured — we extract TTL / window / TCP options from it
    directly, with NO second SYN.  We then send a RST to cleanly close
    the half-open left by port_check.

    Layer-3 (ICMP) probes run independently to corroborate TTL/DF and
    add the quote_len signal.  They are the only new raw packets fired
    by this module (3 packets total: ICMP echo, large echo, UDP unreach).

    If the caller is about to run layer5 (HTTP), they pass
    complete_handshake=True and we ACK the SYN-ACK instead of RST-ing it,
    leaving the connection ready for layer5 to send HTTP probes on.

    Usage
    -----
    from port_check import check_port, PORT_OPEN
    from layer34_probe import Layer34Prober

    state, syn_ack = check_port(ip, port)
    if state == PORT_OPEN:
        prober = Layer34Prober(ip, port, syn_ack)

        # If HTTP will follow, keep connection alive:
        fp = prober.probe(complete_handshake=True)

        # Otherwise tear it down cleanly:
        fp = prober.probe(complete_handshake=False)
    """

    PROBE_TIMEOUT = 2.0

    def __init__(self, ip: str, port: int, syn_ack):
        """
        Parameters
        ----------
        ip       : target IP
        port     : target port (the one port_check opened)
        syn_ack  : the Scapy packet returned by port_check.check_port()
        """
        self.ip      = ip
        self.port    = port
        self.syn_ack = syn_ack   # may be None if caller constructs standalone

    # ── TCP helpers ───────────────────────────────────────────────────

    @staticmethod
    def _opt_string(pkt) -> str:
        """Compact option token string from a TCP packet, e.g. 'M,S,T,N,W'."""
        opt_map = {
            "MSS":       "M",
            "SAckOK":    "S",
            "Timestamp": "T",
            "NOP":       "N",
            "WScale":    "W",
        }
        return ",".join(
            opt_map.get(opt[0], "?") for opt in pkt[TCP].options
        )

    @staticmethod
    def _df_bit(pkt) -> int:
        return 1 if (pkt[IP].flags & 0x02) else 0

    @staticmethod
    def _ecn_echoed(pkt) -> bool:
        return bool(pkt[TCP].flags & 0x40)

    def _extract_syn_ack(self, fingerprint: dict) -> None:
        """
        Pull all layer-4 signals out of the already-captured SYN-ACK.
        No packets sent.
        """
        r = self.syn_ack
        result: Dict[str, Any] = {
            "flags":      int(r[TCP].flags),
            "flag_str":   r[TCP].sprintf("%TCP.flags%"),
            "ttl":        r[IP].ttl,
            "ttl_origin": self._guess_ttl_origin(r[IP].ttl),
            "window":     r[TCP].window,
            "df":         self._df_bit(r),
            "options":    self._opt_string(r),
            "ecn_echoed": self._ecn_echoed(r),
            "port_state": "open",
        }

        fingerprint["tcp_probes"]["syn_rich"] = result

        # Populate top-level keys (these are what the analysis layer reads)
        fingerprint["ttl"]         = result["ttl"]
        fingerprint["ttl_origin"]  = result["ttl_origin"]
        fingerprint["tcp_window"]  = result["window"]
        fingerprint["tcp_options"] = result["options"]
        fingerprint["df_bit"]      = result["df"]

    def _rst(self) -> None:
        """Send RST to close the half-open left by port_check."""
        rst = IP(dst=self.ip) / TCP(
            dport = self.port,
            flags = "R",
            seq   = self.syn_ack[TCP].ack,
        )
        send(rst, verbose=0)

    def _ack(self) -> None:
        """
        Complete the three-way handshake with an ACK, leaving the
        connection ESTABLISHED so layer5 can immediately send HTTP probes
        on the same socket without a new SYN.

        Note: layer5 uses a real socket (not Scapy) for HTTP.  This ACK
        tells the server the connection is up; layer5 then attaches a
        Python socket to the same port tuple and takes over from there.

        In practice on Linux, the kernel will send its own RST when it
        sees the SYN-ACK for a connection it didn't initiate (because
        Scapy bypasses the kernel TCP stack).  The cleanest solution is
        to use an iptables rule to suppress kernel RSTs:

            iptables -A OUTPUT -p tcp --tcp-flags RST RST \
                     -d <target_ip> -j DROP

        layer5 opens its own fresh socket; this ACK is therefore mainly
        a courtesy to avoid leaving the server with a half-open entry.
        """
        ack = IP(dst=self.ip) / TCP(
            dport = self.port,
            sport = self.syn_ack[TCP].dport,
            flags = "A",
            seq   = self.syn_ack[TCP].ack,
            ack   = self.syn_ack[TCP].seq + 1,
        )
        send(ack, verbose=0)

    # ── ICMP helpers ──────────────────────────────────────────────────

    @staticmethod
    def _guess_ttl_origin(ttl: int) -> int:
        if ttl <= 64:  return 64
        if ttl <= 128: return 128
        return 255

    @staticmethod
    def _quote_len(response) -> Optional[int]:
        if not response.haslayer(ICMP):
            return None
        icmp_layer = response[ICMP]
        if icmp_layer.type != 3:
            return None
        return len(bytes(icmp_layer.payload))

    def _send_recv(self, probe_name: str, packet) -> Any:
        response = sr1(packet, timeout=self.PROBE_TIMEOUT, verbose=0)
        if response is None:
            raise RawProbeError(probe_name, self.PROBE_TIMEOUT)
        return response

    def _record_icmp(self,
                     probe_name: str,
                     response,
                     fingerprint: dict) -> None:
        if not response.haslayer(ICMP):
            fingerprint["icmp_probes"][probe_name] = {"error": "no_icmp_layer"}
            return

        icmp   = response[ICMP]
        result: Dict[str, Any] = {
            "icmp_type":  icmp.type,
            "icmp_code":  icmp.code,
            "ttl":        response[IP].ttl,
            "ttl_origin": self._guess_ttl_origin(response[IP].ttl),
            "df":         self._df_bit(response),
            "tos":        response[IP].tos,
            "ip_id":      response[IP].id,
            "quote_len":  self._quote_len(response),
        }

        fingerprint["icmp_probes"][probe_name] = result

        if probe_name == "icmp_echo":
            fingerprint["icmp_ttl"]        = result["ttl"]
            fingerprint["icmp_ttl_origin"] = result["ttl_origin"]
            fingerprint["icmp_df"]         = result["df"]
            fingerprint["icmp_tos"]        = result["tos"]
            # Back-fill top-level ttl only if SYN-ACK extraction failed
            if fingerprint.get("ttl") is None:
                fingerprint["ttl"]       = result["ttl"]
                fingerprint["ttl_origin"]= result["ttl_origin"]

        if probe_name == "icmp_unreach":
            fingerprint["icmp_quote_len"]   = result["quote_len"]
            fingerprint["icmp_unreach_ttl"] = result["ttl"]

    def _mark_error(self,
                    probe_name: str,
                    tag: str,
                    fingerprint: dict) -> None:
        fingerprint["icmp_probe_errors"][probe_name] = tag
        fingerprint["icmp_probes"][probe_name]       = {"error": tag}

    # ── public interface ──────────────────────────────────────────────

    def probe(self,
              fingerprint: Optional[dict] = None,
              complete_handshake: bool = False) -> dict:
        """
        Extract layer-4 data from the captured SYN-ACK, fire ICMP probes,
        and enrich the fingerprint dict.

        Parameters
        ----------
        fingerprint         : pass in dict from a previous layer, or None
        complete_handshake  : if True, ACK the SYN-ACK (layer5 will follow);
                              if False, RST it (this is the last layer)

        Returns
        -------
        dict – enriched fingerprint
        """
        if fingerprint is None:
            fingerprint = {"ip": self.ip, "port": self.port}

        # Ensure all sub-keys exist
        fingerprint.setdefault("ttl",              None)
        fingerprint.setdefault("ttl_origin",       None)
        fingerprint.setdefault("tcp_window",       None)
        fingerprint.setdefault("tcp_options",      None)
        fingerprint.setdefault("df_bit",           None)
        fingerprint.setdefault("tcp_probes",       {})
        fingerprint.setdefault("tcp_probe_errors", {})
        fingerprint.setdefault("icmp_probes",      {})
        fingerprint.setdefault("icmp_probe_errors",{})
        fingerprint.setdefault("icmp_ttl",         None)
        fingerprint.setdefault("icmp_ttl_origin",  None)
        fingerprint.setdefault("icmp_df",          None)
        fingerprint.setdefault("icmp_tos",         None)
        fingerprint.setdefault("icmp_quote_len",   None)
        fingerprint.setdefault("icmp_unreach_ttl", None)
        fingerprint.setdefault("os_family",        None)
        fingerprint.setdefault("web_server",       None)

        # ── Layer-4: extract from SYN-ACK (zero new packets) ─────────
        if self.syn_ack is not None:
            try:
                self._extract_syn_ack(fingerprint)
            except Exception as e:
                fingerprint["tcp_probe_errors"]["syn_rich"] = f"EXTRACT_FAILED:{e}"

            # Resolve the half-open
            try:
                if complete_handshake:
                    self._ack()
                else:
                    self._rst()
            except Exception:
                pass   # best-effort cleanup

        # ── Layer-3: fire ICMP probes ─────────────────────────────────
        icmp_probes = [
            _probe_icmp_echo(self.ip),
            _probe_icmp_echo_large(self.ip),
            _probe_icmp_unreach(self.ip),
        ]

        for probe_name, packet in icmp_probes:
            try:
                response = self._send_recv(probe_name, packet)
                self._record_icmp(probe_name, response, fingerprint)

            except RawProbeError as e:
                self._mark_error(probe_name, f"NO_RESPONSE:{e.timeout}s", fingerprint)

            except PermissionError:
                self._mark_error(probe_name, "PERMISSION_DENIED:run_as_root", fingerprint)
                break

            except Exception as e:
                self._mark_error(probe_name, f"UNEXPECTED:{e}", fingerprint)

        return fingerprint

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python layer34_probe.py <ip> <port>")
        sys.exit(1)

    from port_check import check_port, PORT_OPEN, PortCheckError

    target_ip   = sys.argv[1]
    target_port = int(sys.argv[2])

    try:
        state, syn_ack = check_port(target_ip, target_port)
    except PortCheckError as e:
        print(f"[!] port_check failed: {e}")
        sys.exit(1)

    print(f"[*] Port {target_port}: {state.upper()}")

    if state != PORT_OPEN:
        print("[*] Port not open — running ICMP-only fallback")
        prober = Layer34Prober(target_ip, target_port, syn_ack=None)
    else:
        prober = Layer34Prober(target_ip, target_port, syn_ack)

    fp = prober.probe(complete_handshake=False)

    print(f"\n{'='*55}")
    print(f"  Layer-3/4 probe results  {fp['ip']}:{fp['port']}")
    print(f"{'='*55}")
    print(f"  TTL          : {fp['ttl']}  (origin ~{fp.get('ttl_origin')})")
    print(f"  TCP window   : {fp['tcp_window']}")
    print(f"  TCP options  : {fp['tcp_options']}")
    print(f"  DF bit       : {fp['df_bit']}")
    print(f"  ICMP TTL     : {fp['icmp_ttl']}  (origin ~{fp['icmp_ttl_origin']})")
    print(f"  ICMP DF      : {fp['icmp_df']}")
    print(f"  Quote len    : {fp['icmp_quote_len']} bytes")
    print(f"  TCP errors   : {fp['tcp_probe_errors']}")
    print(f"  ICMP errors  : {fp['icmp_probe_errors']}")
    print(f"{'='*55}\n")
