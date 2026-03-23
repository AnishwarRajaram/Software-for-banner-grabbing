import re

def guess(buffer):
    #print(buffer)
    date_pos = buffer.find("Date:")
    server_pos = buffer.find("Server:")

    if(server_pos!=-1):
        end_pos = server_pos + 7
        newline_pos = buffer.find("\n",end_pos)
        return buffer[end_pos:newline_pos]
        

    if date_pos != -1 and server_pos != -1:
        if date_pos < server_pos:
            return "Apache"
        else:
            return "Not Apache, (could be Nginx)"
            
    return "Unknown: One or both headers missing"
    


            