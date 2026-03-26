from scapy.all import IP,TCP,sr1
import math
import sys
import json


def detOSsignature(pkt):
    if not pkt or not pkt.haslayer(TCP):
        return None
    
    opt_map = {"NOP":'N',"MSS":'M',"WScale":"W","SAckOK":"S","Timestamp":"T"}
    options = []
    #print(pkt[TCP].options)
    for opt in pkt[TCP].options:
        #print(opt[0])
        name = opt_map.get(opt[0], '?')
        options.append(name)
    
    opt_string = ",".join(options)
    
    signature = {
        "TTL": pkt[IP].ttl,
        "Window": pkt[TCP].window,
        "Options": opt_string,
        "DF": 1 if (pkt[IP].flags & 0x02) else 0
    }
    
    print(signature)
    return signature


def signatureMatch(signature, db_path = "os_signatures.json"):
    #print(signature['Options'])
    
    #print(signature['DF'])
    
    with open(db_path, 'r') as f:
        db = json.load(f)
    
    for entry in db['signatures']:
        if (signature['Options'] == entry['options'] and 
            signature['DF'] == entry['df']):
            return entry['os']
            
    return "Unknown OS"





def guessOS(ip):
    TTLtoOS = {64: "Linux/Unix/macOS",
                    128: "Windows",
                    255: "Cisco/Network Device"
    }
    defTCPrcwnd_to_OS = {   5840:"Linux kernel 2.4/2.6",
                            5720: "Google Linux(ChromeOS)",
                            65535: "FreeBSD/OpenBSD/WindowsXP/MacOS",
                            8192: "Windows 7/ Vista 10/11",
                            4128: "Cisco Router(IOS 12.4)"
    }
    flag_list = ["S","R","F"]
    for i in flag_list:
        packet = IP(dst=ip) / TCP(dport=80, flags=f"{i}")
        response = sr1(packet, verbose = 0)
        if(response==None):
            break
        ttl = response.ttl
        ttl = 2**math.ceil(math.log(ttl,2))

        #edge cases
        if ttl < 64: ttl = 64
        elif ttl > 128 and ttl <= 255: ttl = 255

        rcwnd = response[TCP].window
        

        print("possible OS matches (via ttl): "+TTLtoOS[ttl])
        print("possible OS matches(via rcwnd size): " + (defTCPrcwnd_to_OS[rcwnd] if rcwnd in defTCPrcwnd_to_OS.keys() else "None"))
        print("possible OS match(through packet IP signature): " + signatureMatch(detOSsignature(response)))

        #print(ttl)
        return

    print("No responses elicited")

if __name__=="__main__":
    print(sys.argv[1])
    guessOS(sys.argv[1])
    
        




