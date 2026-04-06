import sys
from typing import Optional, Tuple
from scapy.all import IP, TCP, sr1, conf

conf.verb = 0


PORT_OPEN     = "open"
PORT_CLOSED   = "closed"
PORT_FILTERED = "filtered"




class PortCheckError(Exception):
    """Raised on permission errors or unexpected Scapy failures."""
    pass



def check_port(ip: str,
               port: int,
               timeout: float = 2.0) -> Tuple[str, Optional[object]]:
    """
    Send a single SYN with a rich options set and determine port state.

    Returns
    -------
    (state, syn_ack_packet)

    state           : PORT_OPEN | PORT_CLOSED | PORT_FILTERED
    syn_ack_packet  : the raw Scapy response packet if state is PORT_OPEN,
                      else None.

    The SYN-ACK packet is returned intentionally so that layer34_probe can
    extract TTL / window / TCP options from it WITHOUT sending a second SYN.
    We do NOT send a RST here — the caller (layer34 or layer5) is responsible
    for completing or tearing down the half-open connection as appropriate.

    The options set mirrors layer4's syn_rich probe so the SYN-ACK carries
    the fullest possible TCP stack fingerprint.
    """
    opts = [
        ("MSS",       1460),
        ("SAckOK",    b""),
        ("Timestamp", (0, 0)),
        ("NOP",       None),
        ("WScale",    8),
    ]

    try:
        pkt      = IP(dst=ip) / TCP(dport=port, flags="S", options=opts)
        response = sr1(pkt, timeout=timeout, verbose=0)

    except PermissionError:
        raise PortCheckError("PERMISSION_DENIED: run as root / with CAP_NET_RAW")
    except Exception as e:
        raise PortCheckError(f"UNEXPECTED: {e}")

    if response is None:
        return PORT_FILTERED, None

    if not response.haslayer(TCP):
        return PORT_FILTERED, None

    flags = response[TCP].flags

    if (flags & 0x12) == 0x12:          # SYN-ACK
        return PORT_OPEN, response

    if (flags & 0x14) == 0x14:          # RST-ACK
        return PORT_CLOSED, None

    if (flags & 0x04):                  # bare RST
        return PORT_CLOSED, None

    return PORT_FILTERED, None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python port_check.py <ip> <port>")
        sys.exit(1)

    ip_arg   = sys.argv[1]
    port_arg = int(sys.argv[2])

    try:
        state, pkt = check_port(ip_arg, port_arg)
    except PortCheckError as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"\n{'='*45}")
    print(f"  {ip_arg}:{port_arg}  →  {state.upper()}")
    if pkt:
        print(f"  TTL    : {pkt[IP].ttl}")
        print(f"  Window : {pkt[TCP].window}")
    print(f"{'='*45}\n")
