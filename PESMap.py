import HTTPEngine as http
import ftp
import sys
import socket
import OSguesser as osg


def multiserver():
    while input("Want to scan?(?/n)\n")!="n":
        ip = input("enter an ip addr\n")
        service = input("HTTP/HTTPS/FTP\n")
        if(service=="HTTP"):
            http.getfromHTTP(ip,"HTTP")
        elif(service=="HTTPS"):
            http.getfromHTTP(ip,"HTTPS")
        elif(service=="FTP"):
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(4.0)
            port = 21 #(FTP Control port)
            try:
                sock.connect((ip,port))
                banners = ftp.Probe(sock)
                for banner in banners:
                    print(banner)
                sock.close()
                osg.guessOS(ip)
            except TimeoutError:
                print("timeout, server is offline\n")
        

    return





if __name__ == "__main__":
    multiserver()