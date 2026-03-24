from scapy.all import IP,TCP, sr1

def scanPort_SYN(ip, port, timeout):
    packet = IP(dst = ip)/TCP(dport = port, flags = "S")
    response = sr1(packet, timeout = timeout, verbose = 0)
    if response is None:
        return "filtered"
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        sr1(IP(dst=port)/TCP(dport=port, flags = "R"), timeout = 1, verbose = 0)
        return "Open"
    else:
        return "Closed"
        
