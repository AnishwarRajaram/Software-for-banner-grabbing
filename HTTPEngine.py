import socket 
import sys
import ssl
import datetime
import guessWebServer as WBgs
import OSguesser as OSgs

def emptyGET(socket):
    
    probe = (
            "GET / HTTP/1.0\r\n\r\n"
        )
    socket.sendall(probe.encode())
    banner = socket.recv(2048)
    return banner.decode(errors="decode").strip()

def faultyGET(socket,ip):
    probe = (
            f"GET /thispathdoesnotexist HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )
    socket.sendall(probe.encode())
    banner = socket.recv(2048)
    return banner.decode(errors="decode").strip()

def nonExistentVer(socket):
    try:
        probe = (
            "GET / HTTP/9.9"
        )
        socket.sendall(probe.encode())
        banner = socket.recv(2048)
        return banner.decode(errors="decode").strip()
    except ConnectionResetError:
        print("RST packet sent by peer abruptly, moving to next probe...")

def OPTIONS(socket, ip):
    probe = (
        f"OPTIONS * HTTP/1.1\r\n"
        f"Host:{ip}\r\n"
        f"\r\n"
    )
    socket.sendall(probe.encode())
    banner = socket.recv(2048)
    return banner.decode(errors="decode").strip()



def getfromHTTP(ip, protocol = 'HTTP'):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        if(protocol == "HTTP"):
            port = 80
            s.connect((ip, port))
            print(ip)
            banner1 = emptyGET(s)
            banner2 = faultyGET(s,ip)
            banner3 = nonExistentVer(s)
            banner4 = OPTIONS(s, ip)
            s.close()
            print(WBgs.guess(banner1))
            print(WBgs.guess(banner2))
            print(WBgs.guess(banner3))
            print(WBgs.guess(banner4))
            print(OSgs.guessOS(ip))
            #print(banner1,banner2,banner3,banner4)
            #print(f"Script name: {sys.argv[0]}")

            with open("results.txt","w") as file_handle:
                date = datetime.date.today()
                file_handle.write(f"date:{date}\n")
                file_handle.writelines("BANNER1:\n"+banner1+"\n\n\n\n"+"BANNER2:\n"+banner2+"\n\n\n\n"
                                    +"BANNER3:\n"+banner3+"\n\n\n\n"+"BANNER4:\n"+banner4)
                
        elif(protocol == "HTTPS"):
            port = 443
            
        
            s.connect((ip, port))
            context = ssl.create_default_context()
            ssock = context.wrap_socket(s,server_hostname=ip)
            
            banner1 = emptyGET(ssock)
            banner2 = faultyGET(ssock,ip)
            banner3 = nonExistentVer(ssock)
            banner4 = OPTIONS(ssock, ip)
            ssock.close()
            print(WBgs.guess(banner1))
            print(WBgs.guess(banner2))
            print(WBgs.guess(banner3))
            print(WBgs.guess(banner4))
            print(OSgs.guessOS(ip))
            #print(banner1,banner2,banner3,banner4)
            #print(f"Script name: {sys.argv[0]}")

            with open("results.txt","w") as file_handle:
                date = datetime.date.today()
                file_handle.write(f"date:{date}\n")
                file_handle.writelines("BANNER1:\n"+banner1+"\n\n\n\n"+"BANNER2:\n"+banner2+"\n\n\n\n"
                                    +"BANNER3:\n"+banner3+"\n\n\n\n"+"BANNER4:\n"+banner4)
    except TimeoutError:
        print("timeout, server is probably offline-> recheck ip\n")

if __name__ == "__main__":
    getfromHTTP(sys.argv[1])
    
        
    
    
        