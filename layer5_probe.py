import sys
import socket
import ssl
from typing import Optional, Tuple


class ProbeTimeoutError(Exception):
    """Raised when a single HTTP probe exceeds the per-probe timeout."""
    def __init__(self, probe_name: str, timeout: float):
        super().__init__(f"Probe '{probe_name}' timed out after {timeout}s")
        self.probe_name = probe_name
        self.timeout = timeout



def _probe_normal_get(ip: str) -> Tuple[str, bytes]:
    """Standard GET / — most servers respond with full headers."""
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    )
    return "normal_get", req.encode()


def _probe_404_get(ip: str) -> Tuple[str, bytes]:
    """Intentional 404 — error pages often leak server identity."""
    req = (
        f"GET /this_path_does_not_exist_probe HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    )
    return "404_get", req.encode()


def _probe_malformed_http_version(ip: str) -> Tuple[str, bytes]:
    """Non-existent HTTP version — reveals how strictly the server validates."""
    req = "GET / HTTP/9.9\r\n\r\n"
    return "bad_version_get", req.encode()


def _probe_options(ip: str) -> Tuple[str, bytes]:
    """OPTIONS * — exposes allowed methods and sometimes server/OS headers."""
    req = (
        f"OPTIONS * HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"Connection: close\r\n\r\n"
    )
    return "options", req.encode()


class HTTPProber:
    """
    Layer-5 (application) HTTP probe module.

    Usage
    -----
    prober = HTTPProber("192.168.1.10", port=80, protocol="HTTP")
    fingerprint = prober.probe()

    The returned dict is intentionally sparse — downstream layers will
    enrich it with TTL/TCP-stack results and run the final heuristic.
    """

    RECV_BYTES   = 4096
    PROBE_TIMEOUT = 5.0   # seconds per individual probe

    def __init__(self, ip: str, port: int = 80, protocol: str = "HTTP"):
        self.ip       = ip
        self.port     = port
        self.protocol = protocol.upper()  # "HTTP" or "HTTPS"

        # Seed the shared fingerprint dict.
        # Keys added here; values filled in by probe() or left as defaults.
        self.fingerprint: dict = {
            "ip":       ip,
            "port":     port,
            "protocol": self.protocol,
            # ── layer-5 fields (populated below) ──────────────────────
            "http_probes": {
                "normal_get":       None,   # raw response string or error tag
                "404_get":          None,
                "bad_version_get":  None,
                "options":          None,
            },
            "server_header":   None,   # first non-null Server: value seen
            "powered_by":      None,   # X-Powered-By if present
            "status_codes":    {},     # probe_name -> int status code
            "allow_header":    None,   # from OPTIONS response
            "probe_errors":    {},     # probe_name -> error string
            # ── placeholders for later layers ─────────────────────────
            "ttl":             None,
            "tcp_window":      None,
            "tcp_options":     None,
            "os_family":       None,
            "web_server":      None,   # final guess — set by analysis layer
        }

    # ── socket / SSL helpers ──────────────────────────────────────────

    def _open_socket(self) -> socket.socket:
        """
        Open and return a connected TCP socket, optionally TLS-wrapped.
        Caller is responsible for closing it.
        """
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.PROBE_TIMEOUT)
        raw.connect((self.ip, self.port))

        if self.protocol == "HTTPS":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False       # IP-based probing; no valid hostname
            ctx.verify_mode   = ssl.CERT_NONE
            return ctx.wrap_socket(raw, server_hostname=self.ip)

        return raw

    def _recv_all(self, sock: socket.socket, probe_name: str) -> str:
        """
        Read until the server closes the connection or we hit the per-probe
        timeout.  Raises ProbeTimeoutError if the *first* recv times out
        (i.e. server never replies); a mid-stream timeout just means EOF.
        """
        chunks = []
        first_read = True
        while True:
            try:
                chunk = sock.recv(self.RECV_BYTES)
                if not chunk:
                    break
                chunks.append(chunk)
                first_read = False
            except socket.timeout:
                if first_read:
                    raise ProbeTimeoutError(probe_name, self.PROBE_TIMEOUT)
                break   
        return b"".join(chunks).decode(errors="ignore").strip()

    def _send_recv_on(self, sock: socket.socket,
                      probe_name: str, payload: bytes) -> str:
        """Send payload on an already-open socket and read the response."""
        sock.sendall(payload)
        return self._recv_all(sock, probe_name)

    
    @staticmethod
    def _extract_status_code(response: str) -> Optional[int]:
        """Parse HTTP status code from the first line, e.g. 'HTTP/1.1 200 OK'."""
        try:
            first_line = response.splitlines()[0]
            return int(first_line.split()[1])
        except (IndexError, ValueError):
            return None

    @staticmethod
    def _extract_header(response: str, header_name: str) -> Optional[str]:
        """Case-insensitive single-header extraction."""
        needle = header_name.lower() + ":"
        for line in response.splitlines():
            if line.lower().startswith(needle):
                return line.split(":", 1)[1].strip()
        return None

    # ── internal helper ───────────────────────────────────────────────

    def _record(self, probe_name: str, response: str) -> None:
        """Parse a response string and write extracted fields into fingerprint."""
        self.fingerprint["http_probes"][probe_name] = response

        status = self._extract_status_code(response)
        if status:
            self.fingerprint["status_codes"][probe_name] = status

        server = self._extract_header(response, "Server")
        if server and self.fingerprint["server_header"] is None:
            self.fingerprint["server_header"] = server

        powered = self._extract_header(response, "X-Powered-By")
        if powered and self.fingerprint["powered_by"] is None:
            self.fingerprint["powered_by"] = powered

        if probe_name == "options":
            allow = self._extract_header(response, "Allow")
            if allow:
                self.fingerprint["allow_header"] = allow

    def _mark_error(self, probe_name: str, tag: str) -> None:
        self.fingerprint["probe_errors"][probe_name]  = tag
        self.fingerprint["http_probes"][probe_name]   = "PROBE_ERROR"

    # ── public interface ─────────────────────────────────────────────

    def probe(self,
              fingerprint: Optional[dict] = None,
              port_state:  str            = "open") -> dict:
        """
        Fire all four HTTP probes and populate the fingerprint dict.

        Parameters
        ----------
        fingerprint : dict, optional
            Pass the dict returned by Layer34Prober.probe() to keep building
            on the same object.  If omitted, self.fingerprint is used.
        port_state  : str
            The value returned by port_check.check_port().  If it is not
            "open" this method immediately marks all probes as SKIPPED and
            returns — no sockets are opened, no packets are sent.

        Strategy
        --------
        Probes 1–3 (normal_get, 404_get, options) share ONE persistent
        TCP connection using HTTP/1.1 keep-alive, saving two round-trip
        handshakes.  bad_version_get (HTTP/9.9) gets its own socket because
        servers typically close the connection on a malformed request line.

        Returns
        -------
        dict – the fingerprint dict
        """
        # Merge incoming fingerprint so all prior-layer keys are preserved
        if fingerprint is not None:
            for k, v in fingerprint.items():
                self.fingerprint.setdefault(k, v)
            fingerprint.update(self.fingerprint)
            self.fingerprint = fingerprint

        # Gate: skip HTTP entirely if the port is not confirmed open
        if port_state != "open":
            skip_tag = f"SKIPPED:port_{port_state}"
            for probe_name in self.fingerprint["http_probes"]:
                self._mark_error(probe_name, skip_tag)
            return self.fingerprint

        # ── Group 1: persistent connection for well-behaved probes ────
        persistent_probes = [
            _probe_normal_get(self.ip),
            _probe_404_get(self.ip),
            _probe_options(self.ip),
        ]

        # Build payloads with keep-alive on all but the last one
        payloads = []
        for i, (name, raw) in enumerate(persistent_probes):
            is_last = (i == len(persistent_probes) - 1)
            # Replace "Connection: close" with keep-alive for all but last
            adjusted = raw.replace(
                b"Connection: close",
                b"Connection: close" if is_last else b"Connection: keep-alive"
            )
            payloads.append((name, adjusted))

        try:
            sock = self._open_socket()
            try:
                for probe_name, payload in payloads:
                    try:
                        response = self._send_recv_on(sock, probe_name, payload)
                        self._record(probe_name, response)
                    except ProbeTimeoutError as e:
                        self._mark_error(probe_name, f"TIMEOUT:{e.timeout}s")
                    except OSError as e:
                        self._mark_error(probe_name, f"OS_ERROR:{e}")
                        break   # socket is dead; skip remaining keep-alive probes
                    except Exception as e:
                        self._mark_error(probe_name, f"UNEXPECTED:{e}")
            finally:
                sock.close()

        except socket.timeout:
            # Could not even connect
            for name, _ in persistent_probes:
                if self.fingerprint["http_probes"][name] is None:
                    self._mark_error(name, f"TIMEOUT:{self.PROBE_TIMEOUT}s")
        except OSError as e:
            for name, _ in persistent_probes:
                if self.fingerprint["http_probes"][name] is None:
                    self._mark_error(name, f"OS_ERROR:{e}")

        # ── Group 2: bad_version_get on its own socket ────────────────
        bv_name, bv_payload = _probe_malformed_http_version(self.ip)
        try:
            sock = self._open_socket()
            try:
                response = self._send_recv_on(sock, bv_name, bv_payload)
                self._record(bv_name, response)
            except ProbeTimeoutError as e:
                self._mark_error(bv_name, f"TIMEOUT:{e.timeout}s")
            except Exception as e:
                self._mark_error(bv_name, f"UNEXPECTED:{e}")
            finally:
                sock.close()
        except socket.timeout:
            self._mark_error(bv_name, f"TIMEOUT:{self.PROBE_TIMEOUT}s")
        except OSError as e:
            self._mark_error(bv_name, f"OS_ERROR:{e}")

        return self.fingerprint



class FTPProber:
    """
    Layer-5 (application) FTP probe module.

    FTP is a command/response protocol where the server speaks first
    (220 banner).  All probes run sequentially on ONE persistent
    connection — no reconnect needed between commands.

    Probes fired (in order):
        banner          — read the 220 greeting immediately on connect
        syst            — SYST: server OS / platform hint
        feat            — FEAT: supported extensions list
        anon_login      — USER anonymous / PASS anonymous@
        csid            — CSID (client identification, vsftpd/ProFTPD extension)

    The anon_login probe is intentionally low-risk: most servers either
    accept it (pure FTP servers in a lab) or reject it with 530 — either
    way the response text often contains the software version.

    Usage
    -----
    prober = FTPProber("192.168.1.10", port=21)
    fp     = prober.probe(fingerprint, port_state)
    """

    RECV_BYTES    = 4096
    PROBE_TIMEOUT = 5.0
    # Codes that mean "go ahead, keep sending commands"
    _CONTINUE_CODES = {220, 211, 215, 230, 331, 500, 502, 530}

    def __init__(self, ip: str, port: int = 21):
        self.ip   = ip
        self.port = port

        self.fingerprint: dict = {
            "ip":   ip,
            "port": port,
            # ── FTP-specific fields ────────────────────────────────────
            "ftp_probes": {
                "banner":     None,
                "syst":       None,
                "feat":       None,
                "anon_login": None,
                "csid":       None,
            },
            "ftp_banner":       None,   # raw 220 greeting text
            "ftp_software":     None,   # extracted from banner / SYST
            "ftp_anon_allowed": None,   # True / False / None (unknown)
            "ftp_features":     [],     # list of FEAT tokens
            "ftp_probe_errors": {},
            
            "ttl":        None,
            "tcp_window": None,
            "tcp_options":None,
            "os_family":  None,
            "web_server": None,
        }

    # ── socket helper ─────────────────────────────────────────────────

    def _open_socket(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.PROBE_TIMEOUT)
        s.connect((self.ip, self.port))
        return s

    # ── send / recv helpers ───────────────────────────────────────────

    def _recv_response(self, sock: socket.socket, probe_name: str) -> str:
        """
        Read a complete FTP response (may span multiple lines for multi-line
        replies like FEAT).  Stops when it sees a line matching the terminal
        pattern: 3-digit code followed by a space (not a dash).
        Raises ProbeTimeoutError on first-read timeout.
        """
        chunks = []
        first_read = True
        buf = ""
        while True:
            try:
                chunk = sock.recv(self.RECV_BYTES).decode(errors="ignore")
                if not chunk:
                    break
                buf += chunk
                first_read = False
                # FTP terminal line: "NNN <text>\r\n" (dash = continuation)
                lines = buf.splitlines()
                for line in lines:
                    if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
                        return buf.strip()
            except socket.timeout:
                if first_read:
                    raise ProbeTimeoutError(probe_name, self.PROBE_TIMEOUT)
                break
        return buf.strip()

    def _send_cmd(self, sock: socket.socket,
                  probe_name: str, cmd: str) -> str:
        """Send one FTP command and read the response."""
        sock.sendall((cmd + "\r\n").encode())
        return self._recv_response(sock, probe_name)

    # ── response parsers ─────────────────────────────────────────────

    @staticmethod
    def _ftp_code(response: str) -> Optional[int]:
        """Extract the 3-digit FTP reply code from the first line."""
        try:
            return int(response.splitlines()[0][:3])
        except (IndexError, ValueError):
            return None

    @staticmethod
    def _parse_features(feat_response: str) -> list:
        """
        Parse the FEAT response into a clean list of feature tokens.
        FEAT response format:
            211-Features:
             MLST size*;...
             UTF8
            211 End
        """
        features = []
        for line in feat_response.splitlines():
            stripped = line.strip()
            # Skip the opening 211- line and closing 211 End line
            if stripped.startswith("211"):
                continue
            if stripped:
                features.append(stripped.split()[0].upper())
        return features

    @staticmethod
    def _extract_software(banner: str) -> Optional[str]:
        """
        Try to pull a software name/version from the 220 banner.
        Common patterns:
            220 ProFTPD 1.3.5 Server (ProFTPD) [::ffff:x.x.x.x]
            220 (vsFTPd 3.0.3)
            220 FileZilla Server 0.9.60 beta
            220 Microsoft FTP Service
        """
        if not banner:
            return None
        # Grab everything after the leading "220 " or "220-"
        for line in banner.splitlines():
            line = line.strip()
            if line.startswith("220"):
                text = line[3:].lstrip("-").strip()
                if text:
                    return text
        return None

    # ── internal helpers ──────────────────────────────────────────────

    def _record(self, probe_name: str, response: str) -> None:
        """Write a response into the fingerprint and extract relevant fields."""
        self.fingerprint["ftp_probes"][probe_name] = response
        code = self._ftp_code(response)

        if probe_name == "banner":
            self.fingerprint["ftp_banner"]   = response
            self.fingerprint["ftp_software"] = self._extract_software(response)

        elif probe_name == "feat":
            if code == 211:
                self.fingerprint["ftp_features"] = self._parse_features(response)

        elif probe_name == "anon_login":
            # 230 = logged in, 331 = need password (sent after USER),
            # 530 = not allowed
            if code == 230:
                self.fingerprint["ftp_anon_allowed"] = True
            elif code == 530:
                self.fingerprint["ftp_anon_allowed"] = False
            # 331 means USER was accepted, PASS probe will determine final result

        # If software still unknown, try SYST response
        if probe_name == "syst" and self.fingerprint["ftp_software"] is None:
            if code == 215:
                self.fingerprint["ftp_software"] = response.split(" ", 1)[-1].strip()

    def _mark_error(self, probe_name: str, tag: str) -> None:
        self.fingerprint["ftp_probe_errors"][probe_name] = tag
        self.fingerprint["ftp_probes"][probe_name]       = "PROBE_ERROR"

    # ── public interface ─────────────────────────────────────────────

    def probe(self,
              fingerprint: Optional[dict] = None,
              port_state:  str            = "open") -> dict:
        """
        Open one FTP connection, fire all probes in sequence, close.

        Parameters
        ----------
        fingerprint : dict, optional
            Accumulated fingerprint from prior layers.
        port_state  : str
            From port_check.check_port().  Skips all probes if not "open".

        Returns
        -------
        dict – enriched fingerprint
        """
        # Merge incoming fingerprint
        if fingerprint is not None:
            for k, v in fingerprint.items():
                self.fingerprint.setdefault(k, v)
            fingerprint.update(self.fingerprint)
            self.fingerprint = fingerprint

        # Gate: skip if port not open
        if port_state != "open":
            skip_tag = f"SKIPPED:port_{port_state}"
            for probe_name in self.fingerprint["ftp_probes"]:
                self._mark_error(probe_name, skip_tag)
            return self.fingerprint

        # ── Single persistent FTP connection ─────────────────────────
        try:
            sock = self._open_socket()
        except socket.timeout:
            for p in self.fingerprint["ftp_probes"]:
                self._mark_error(p, f"TIMEOUT:{self.PROBE_TIMEOUT}s")
            return self.fingerprint
        except OSError as e:
            for p in self.fingerprint["ftp_probes"]:
                self._mark_error(p, f"OS_ERROR:{e}")
            return self.fingerprint

        try:
            # ── 1. Banner — server speaks first ───────────────────────
            try:
                banner = self._recv_response(sock, "banner")
                self._record("banner", banner)
                code = self._ftp_code(banner)
                if code not in self._CONTINUE_CODES:
                    # Server immediately rejected — tag remaining and bail
                    for p in ["syst", "feat", "anon_login", "csid"]:
                        self._mark_error(p, f"ABORTED:banner_code_{code}")
                    return self.fingerprint
            except ProbeTimeoutError as e:
                self._mark_error("banner", f"TIMEOUT:{e.timeout}s")
                for p in ["syst", "feat", "anon_login", "csid"]:
                    self._mark_error(p, "ABORTED:no_banner")
                return self.fingerprint

            # ── 2. SYST ───────────────────────────────────────────────
            try:
                self._record("syst", self._send_cmd(sock, "syst", "SYST"))
            except ProbeTimeoutError as e:
                self._mark_error("syst", f"TIMEOUT:{e.timeout}s")
            except OSError as e:
                self._mark_error("syst", f"OS_ERROR:{e}")

            # ── 3. FEAT ───────────────────────────────────────────────
            try:
                self._record("feat", self._send_cmd(sock, "feat", "FEAT"))
            except ProbeTimeoutError as e:
                self._mark_error("feat", f"TIMEOUT:{e.timeout}s")
            except OSError as e:
                self._mark_error("feat", f"OS_ERROR:{e}")

            # ── 4. Anonymous login (USER then PASS on same connection) ─
            try:
                user_resp = self._send_cmd(sock, "anon_login", "USER anonymous")
                user_code = self._ftp_code(user_resp)
                if user_code == 331:
                    # Server wants password — send it and record combined result
                    pass_resp = self._send_cmd(sock, "anon_login", "PASS anonymous@")
                    self._record("anon_login", pass_resp)
                else:
                    self._record("anon_login", user_resp)
            except ProbeTimeoutError as e:
                self._mark_error("anon_login", f"TIMEOUT:{e.timeout}s")
            except OSError as e:
                self._mark_error("anon_login", f"OS_ERROR:{e}")

            # ── 5. CSID (vsftpd / ProFTPD extension) ──────────────────
            try:
                self._record("csid",
                    self._send_cmd(sock, "csid", "CSID Name=probe; Version=1.0;"))
            except ProbeTimeoutError as e:
                self._mark_error("csid", f"TIMEOUT:{e.timeout}s")
            except OSError as e:
                self._mark_error("csid", f"OS_ERROR:{e}")

        finally:
            # Polite QUIT before closing
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
            sock.close()

        return self.fingerprint

if __name__ == "__main__":
    """
    Usage examples:
        python layer5_probe.py <ip> 80          # HTTP
        python layer5_probe.py <ip> 443 HTTPS   # HTTPS
        python layer5_probe.py <ip> 21  FTP     # FTP
        python layer5_probe.py <ip> 80  HTTP    # explicit HTTP
    """
    if len(sys.argv) < 3:
        print("Usage: python layer5_probe.py <ip> <port> [HTTP|HTTPS|FTP]")
        sys.exit(1)

    target_ip   = sys.argv[1]
    target_port = int(sys.argv[2])

    # Infer protocol from port if not given
    if len(sys.argv) > 3:
        proto = sys.argv[3].upper()
    else:
        proto = {21: "FTP", 443: "HTTPS"}.get(target_port, "HTTP")

    from port_check    import check_port, PORT_OPEN, PortCheckError
    from layer34_probe import Layer34Prober

    # ── 1. Port check ─────────────────────────────────────────────────
    try:
        state, syn_ack = check_port(target_ip, target_port)
    except PortCheckError as e:
        print(f"[!] port_check failed: {e}")
        sys.exit(1)

    print(f"[*] Port {target_port}: {state.upper()}")

    # ── 2. Layer 3/4 ─────────────────────────────────────────────────
    # complete_handshake only needed if HTTP/HTTPS will follow
    # (FTP opens its own socket; layer34 can RST cleanly)
    http_will_follow = (state == PORT_OPEN and proto in ("HTTP", "HTTPS"))
    prober34 = Layer34Prober(target_ip, target_port,
                             syn_ack if state == PORT_OPEN else None)
    fp = prober34.probe(complete_handshake=http_will_follow)

    # ── 3. Layer 5 ───────────────────────────────────────────────────
    if proto == "FTP":
        prober5 = FTPProber(target_ip, target_port)
        fp = prober5.probe(fingerprint=fp, port_state=state)

        print(f"\n{'='*55}")
        print(f"  FTP probe results  {fp['ip']}:{fp['port']}")
        print(f"{'='*55}")
        print(f"  TTL          : {fp.get('ttl')}  (origin ~{fp.get('ttl_origin')})")
        print(f"  TCP window   : {fp.get('tcp_window')}")
        print(f"  TCP options  : {fp.get('tcp_options')}")
        print(f"  DF bit       : {fp.get('df_bit')}")
        print(f"  ICMP TTL     : {fp.get('icmp_ttl')}")
        print(f"  FTP software : {fp.get('ftp_software')}")
        print(f"  Anon login   : {fp.get('ftp_anon_allowed')}")
        print(f"  Features     : {fp.get('ftp_features')}")
        print(f"  FTP errors   : {fp.get('ftp_probe_errors')}")
        print(f"  TCP errors   : {fp.get('tcp_probe_errors')}")
        print(f"  ICMP errors  : {fp.get('icmp_probe_errors')}")
        print(f"{'='*55}\n")

        for name, resp in fp.get("ftp_probes", {}).items():
            print(f"── {name} ──")
            if resp and "PROBE_ERROR" not in str(resp) and "SKIPPED" not in str(resp):
                print(resp[:300])
            else:
                print(f"  [{resp}]")
            print()

    else:
        prober5 = HTTPProber(target_ip, target_port, proto)
        fp = prober5.probe(fingerprint=fp, port_state=state)

        print(f"\n{'='*55}")
        print(f"  HTTP probe results  {fp['ip']}:{fp['port']} ({fp.get('protocol')})")
        print(f"{'='*55}")
        print(f"  TTL          : {fp.get('ttl')}  (origin ~{fp.get('ttl_origin')})")
        print(f"  TCP window   : {fp.get('tcp_window')}")
        print(f"  TCP options  : {fp.get('tcp_options')}")
        print(f"  DF bit       : {fp.get('df_bit')}")
        print(f"  ICMP TTL     : {fp.get('icmp_ttl')}")
        print(f"  Quote len    : {fp.get('icmp_quote_len')} bytes")
        print(f"  Server hdr   : {fp.get('server_header')}")
        print(f"  X-Powered-By : {fp.get('powered_by')}")
        print(f"  Allow hdr    : {fp.get('allow_header')}")
        print(f"  Status codes : {fp.get('status_codes')}")
        print(f"  HTTP errors  : {fp.get('probe_errors')}")
        print(f"  TCP errors   : {fp.get('tcp_probe_errors')}")
        print(f"  ICMP errors  : {fp.get('icmp_probe_errors')}")
        print(f"{'='*55}\n")

        for name, resp in fp.get("http_probes", {}).items():
            print(f"── {name} ──")
            if resp and "PROBE_ERROR" not in str(resp) and "SKIPPED" not in str(resp):
                print(resp[:300])
            else:
                print(f"  [{resp}]")
            print()
