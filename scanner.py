import socket
import sys

def check_host(ip):
    try:
        # Attempt to connect to a common port to verify if the host is "on"
        socket.setdefaulttimeout(0.1)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 80))
        return True
    except:
        return False

# Example: Scanning a local subnet range
'''base_ip = "192.168.0."
for i in range(1, 255):
    target = f"{base_ip}{i}"
    if check_host(target):
        print(target, flush=True)
'''

target = "192.168.0.100"
if check_host(target):
    print(target, flush=True)
