import socket 
import sys
import ssl
import datetime
import guessWebServer as WBgs
import OSguesser as OSgs

SESSION = 1

def emptyGET(sock, ip):
    probe = "GET / HTTP/1.0\r\n\r\n"
    sock.sendall(probe.encode())
    return sock.recv(2048).decode(errors="ignore").strip()

def faultyGET(sock, ip):
    probe = (
        f"GET /thispathdoesnotexist HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock.sendall(probe.encode())
    return sock.recv(2048).decode(errors="ignore").strip()

def nonExistentVer(sock, ip):
    probe = "GET / HTTP/9.9\r\n\r\n"
    sock.sendall(probe.encode())
    return sock.recv(2048).decode(errors="ignore").strip()

def OPTIONS(sock, ip):
    probe = (
        f"OPTIONS * HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"\r\n"
    )
    sock.sendall(probe.encode())
    return sock.recv(2048).decode(errors="ignore").strip()

def run_probe(ip, port, protocol, probe_func):
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0) # 5 seconds is plenty for a banner response
        s.connect((ip, port))
        
        target_sock = s
        if protocol == "HTTPS":
            context = ssl.create_default_context()
            # Basic cert validation bypass often needed for IP-based probing
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            target_sock = context.wrap_socket(s, server_hostname=ip)
        
        result = probe_func(target_sock, ip)
        target_sock.close()
        return result
    except Exception as e:
        return f"Probe Failed: {e}"

def getfromHTTP(ip, protocol='HTTP'):
    port = 80 if protocol == "HTTP" else 443
    print(f"[*] Starting scan on {ip}:{port} ({protocol})")

    # Execute all probes independently
    banner1 = run_probe(ip, port, protocol, emptyGET)
    banner2 = run_probe(ip, port, protocol, faultyGET)
    banner3 = run_probe(ip, port, protocol, nonExistentVer)
    banner4 = run_probe(ip, port, protocol, OPTIONS)

    # Print Guesses
    print(f"Probe 1 Guess: {WBgs.guess(banner1)}")
    print(f"Probe 2 Guess: {WBgs.guess(banner2)}")
    print(f"Probe 3 Guess: {WBgs.guess(banner3)}")
    print(f"Probe 4 Guess: {WBgs.guess(banner4)}")
    
    # Run Scapy OS Guesser
    try:
        print(OSgs.guessOS(ip))
    except Exception as e:
        print(f"OS Guesser failed: {e}")

    # Log results
    filename = "results.txt" if protocol == "HTTP" else f"results_{SESSION}.txt"
    with open(filename, "w") as file_handle:
        date = datetime.date.today()
        file_handle.write(f"Date: {date}\nTarget: {ip}\n\n")
        file_handle.write(f"BANNER1:\n{banner1}\n\n"
                          f"BANNER2:\n{banner2}\n\n"
                          f"BANNER3:\n{banner3}\n\n"
                          f"BANNER4:\n{banner4}")
    print(f"[*] Results saved to {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python HTTPEnigne.py <IP>")
    else:
        getfromHTTP(sys.argv[1])