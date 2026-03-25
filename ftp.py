import socket
import sys
import datetime

def Probe(s):
    banner1 = s.recv(2048)    

    probe = "SYST\r\n"
    s.sendall(probe.encode())
    banner2 = s.recv(2048)

    probe = "FEAT\r\n"
    s.sendall(probe.encode())
    banner3 = s.recv(2048)

    probe = "USER anonymous\r\n"
    s.sendall(probe.encode())
    banner4 = s.recv(2048)

    probe = "PASS anonymous\r\n"
    s.sendall(probe.encode())
    banner5 = s.recv(2048)

    probe = "CSID client123\r\n"
    s.sendall(probe.encode())
    banner6 = s.recv(2048)

    banners = []
    banners.append(banner1)
    banners.append(banner2)
    banners.append(banner3)
    banners.append(banner4)
    banners.append(banner5)
    banners.append(banner6)

    for b in banners:
        b.decode(errors = "ignore").strip()

    return banners

if __name__ == "__main__":
    ip = sys.argv[1]
    port = 21

    print(ip)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    # single function for all banner info
    Banners = Probe(s)

    s.close()

    # Print results
    print("Initial Banner:\n", Banners[0])
    print("\nSYST Response:\n", Banners[1])
    print("\nFEAT Response:\n", Banners[2])
    print("\nUSER Response:\n", Banners[3])
    print("\nUSER Response:\n", Banners[4])
    print("\nCSID Response:\n", Banners[5])

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
