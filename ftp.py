import socket
import sys
import datetime

def getBanner(s):
    banner = s.recv(2048)
    return banner.decode(errors="ignore").strip()

def userProbe(s):
    probe = "USER anonymous\r\n"
    s.sendall(probe.encode())
    banner = s.recv(2048)
    return banner.decode(errors="ignore").strip()

def passProbe(s):
    probe = "PASS anonymous\r\n"
    s.sendall(probe.encode())
    banner = s.recv(2048)
    return banner.decode(errors="ignore").strip()

def helpProbe(s):
    probe = "HELP\r\n"
    s.sendall(probe.encode())
    banner = s.recv(2048)
    return banner.decode(errors="ignore").strip()

def invalidCommand(s):
    probe = "FAKECMD\r\n"
    s.sendall(probe.encode())
    banner = s.recv(2048)
    return banner.decode(errors="ignore").strip()

def systProbe(s):
    probe = "SYST\r\n"
    s.sendall(probe.encode())
    banner = s.recv(2048)
    return banner.decode(errors="ignore").strip()

def extraProbe(s):
    probe = "FEAT\r\n"
    s.sendall(probe.encode())
    banner = s.recv(2048)
    return banner.decode(errors = "ignore").strip()


if __name__ == "__main__":
    ip = sys.argv[1]
    port = 21

    print(ip)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    banner1 = getBanner(s)        # Initial FTP banner
    banner2 = userProbe(s)        # USER response
    banner3 = passProbe(s)        # PASS response
    banner4 = helpProbe(s)        # HELP response
    banner5 = invalidCommand(s)   # Invalid command response
    banner6 = systProbe(s)        # OS info (very useful)
    banner7 = extraProbe(s)       # We can use FEAT or CSID here for more server info

    s.close()

    # Print results
    print("Initial Banner:\n", banner1)
    print("\nUSER Response:\n", banner2)
    print("\nPASS Response:\n", banner3)
    print("\nHELP Response:\n", banner4)
    print("\nInvalid Command Response:\n", banner5)
    print("\nSYST Response:\n", banner6)
    print("\nExtra Probe Repsonse:\n" , banner7)

    # # Save to file
    # with open("results.txt", "w") as file_handle:
    #     date = datetime.date.today()
    #     file_handle.write(f"date:{date}\n\n")

    #     file_handle.write("BANNER1 (Initial):\n" + banner1 + "\n\n\n")
    #     file_handle.write("BANNER2 (USER):\n" + banner2 + "\n\n\n")
    #     file_handle.write("BANNER3 (PASS):\n" + banner3 + "\n\n\n")
    #     file_handle.write("BANNER4 (HELP):\n" + banner4 + "\n\n\n")
    #     file_handle.write("BANNER5 (INVALID CMD):\n" + banner5 + "\n\n\n")
    #     file_handle.write("BANNER6 (SYST):\n" + banner6 + "\n")