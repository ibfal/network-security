#sources
#https://scapy.readthedocs.io/en/latest/usage.html
#https://www.youtube.com/watch?v=yD8qrP8sCDs
#the slides with the skel code.
#also asked allison what you had said about it not showing 
#in wireshark.

from scapy.all import *

vic_ip = "131.229.235.88" #my IP is 131.229.235.87, but this doesnt show up in wireshark when i use my own
attack_ip = "127.0.0.1"

I = IP(src = attack_ip, dst = vic_ip) 
T = TCP(sport=135, dport=135, flags='S') 

pkt = I/T
sendp(pkt) #sr(pkt) just prints dots to comand line so i have to terminate it. 
