import socket
import ssl

def banner_grab(ip, port, message=None, timeout=9):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        if int(port) != 80 or int(port) != 8443:
            ssl_context = ssl.create_default_context();

            ssl_context.check_hostname = False;

            ssl_context.verify_mode = ssl.CERT_NONE

            ssl_context.set_ciphers("DEFAULT:@SECLEVEL=0")
            
            httpsSocket = ssl_context.wrap_socket(s)
        else:
            httpsSocket = s
        
        if message:
            httpsSocket.send(message.encode())
        
        banner = httpsSocket.recv(1024)
        httpsSocket.close()
        
        return banner.decode(errors='ignore').strip()
    
    except Exception as e:
        return f"Error: {e}"
    

if __name__ == "__main__":
    message = "GET / HTTP/1.0\r\n\r\n";
    ip  = "192.168.254.1"
    port = 8443

    print(banner_grab(ip,port,message))
    
