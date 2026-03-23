from scapy.all import IP,TCP,sr1
import math
import sys

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
        response = sr1(packet)
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

        #print(ttl)
        return

    print("No responses elicited")

if __name__=="__main__":
    print(sys.argv[1])
    guessOS(sys.argv[1])
    
        




