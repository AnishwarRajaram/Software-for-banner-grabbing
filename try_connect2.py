import socket
import ssl

def banner_grab(ip, port, timeout=9):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        
        
        if int(port) != 80:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) 
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.set_ciphers("DEFAULT:@SECLEVEL=0:ALL:COMPLEMENTOFALL")
            
            conn = ssl_context.wrap_socket(s, server_hostname=ip)
        else:
            conn = s
        
        
        probe = (
            f"GET /thispathdoesnotexist HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        
        conn.sendall(probe.encode())
        
       
        banner = conn.recv(4096)
        conn.close()
        
        return banner.decode(errors='ignore').strip()
    
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    target_ip = ""
    target_port = 8443
    print(banner_grab(target_ip, target_port))
    banner_grab(target_ip, target_port)
    
