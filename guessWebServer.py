import re

def guess(buffer):
    if not buffer or "Probe Error" in buffer:
        return "No Response"

    
    lines = buffer.split('\n')
    for line in lines:
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()

    # Fallback if Server header is missing but body contains clues
    low_buf = buffer.lower()
    if "nginx" in low_buf:
        return "Nginx (detected via body/error page)"
    if "apache" in low_buf:
        return "Apache (detected via body/error page)"
    
    # Fallback #2
    date_pos = buffer.find("Date:")
    server_pos = buffer.find("Server:")
    if date_pos != -1 and server_pos != -1:
        if date_pos < server_pos:
            return "Apache"
        else:
            return "Not Apache, (could be Nginx)"
            
            
    return "Unknown: Headers missing"


            