import socket
import sys
import argparse
import re 
import random
from datetime import datetime
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import * 


#variables
allports = list(range(0,65,536))
knownports= list(range(0, 1024))

#functions:
def checkform(target):
#https://stackoverflow.com/questions/13970028/how-to-find-if-the-user-have-entered-hostname-or-ip-address
    try:
        checkform = re.compile('\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        ipform = checkform.match(target)
        if not ipform:
            #if we are here it is not an IP address and it must be a Host name that we need to convert.
            targetIP = str(socket.gethostbyname(target))
        else: 
            targetIP = str(target)
            #it was an IP address, continue. 
    except socket.gaierror:
        print("This is an invalid hostname/IP address. Please try again")
    return targetIP
        
def ping(targetIP):
    ping = IP(dst=targetIP)/ICMP()
    pingrsp = sr1(ping, verbose = 0)
    if pingrsp == None:
        status = "This host is unreachable." 
    else:
        status= "up"
    return status

def randOrder(portset):
    randord = random.sample(portset,len(portset))
    return randord
    
def printout(timeend, timestart, closedcount, openports, mode):
    if mode == "connect":
        totaltime= timeend-timestart
        print()
        print("Not Shown: " + str(closedcount) + " closed ports")
        print()
        print("PORT" + "     " + "STATE" + "     " + "SERVICE" + "     " + "BANNER")
        for line in openports:
            print(line[0] + "         " + line[1] + "     " + line[2] + "     " +str (line[3]))
            print()  
        print("Scan done!" + "\n" + "1 IP Address (1 host) scanned in "+ str(totaltime) + " seconds")
    
    elif mode == "syn":
        totaltime= timeend-timestart
        print()
        print("Not Shown: " + str(closedcount) + " closed ports")
        print()
        print("PORT" + "     " + "STATE" + "     " + "SERVICE" )
        for line in openports:
            print(line[0] + "         " + line[1] + "     " + line[2])
            print()  
        print("Scan done!" + "\n" + "1 IP Address (1 host) scanned in "+ str(totaltime) + " seconds")
    
    elif mode == "udp":
        totaltime= timeend-timestart
        print()
        print("Not Shown: " + str(closedcount) + " open/filtered ports")
        print()
        print("PORT" + "     " + "STATE" + "     " + "SERVICE" )
        for line in openports:
            print(line[0] + "         " + line[1] + "     " + line[2] )
            print()  
        print("Scan done!" + "\n" + "1 IP Address (1 host) scanned in "+ str(totaltime) + " seconds")

def getbanner(sock, targetIP, port): 
    request = f"GET / HTTP/1.1\r\nHost: {targetIP}:{port}\r\n\r\n".encode()
    banner = ""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # sending request
    sock.sendall(request)
    # receiving response
    while True:
        try:
            recv = sock.recv(1024)
            if recv == b'':
                break
            banner += recv.decode()
        except:
            pass
    keep= banner.split('\r\n\r\n')
    banner= keep[0].replace("\r\n","  ") 
    return banner

def cscan(targetIP, ports):
    closedcount = 0
    openports = []
    status = False
    for port in ports:
        print(".", end="",flush = True)
        respon = sr1(IP(dst=targetIP)/TCP(sport=135,dport=port,flags="S"),verbose = 0, timeout=.1)
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(.1) 
            s.connect((targetIP, port)) 
            status = True
        except:
            status = False
            closedcount += 1
        if status:
            s.settimeout(None)
            banner = getbanner(s, targetIP, port)
            service = socket.getservbyport(port) 
            openports.append([str(port), "Open", str(service), str(banner)])
    timeend = datetime.now()
    return (closedcount, openports, timeend)

def synscan(targetIP, ports):
    closedcount = 0
    openports = []
    for port in ports:
        print(".", end="",flush = True)
        respon = sr1(IP(dst = targetIP)/TCP(sport = 135, dport = port, flags = "S"),verbose = 0, timeout=.1)
        if (str(type(respon)) == "<class 'NoneType'>"): 
            state = "Filtered" 
            #try:
                #service = socket.getservbyport(int(port), 'tcp')
                #state = "Open"
            #except:
                #service = "No Service Found"
            #service = socket.getservbyport(port, 'tcp')
            #openports.append([str(port), state, str(service)])
        elif(respon.haslayer(TCP)):
            if(respon.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst = targetIP)/TCP(sport= 135, dport=port,flags="R"), verbose = 0, timeout=.5)
                state = "Open"
                service = socket.getservbyport(port)
                openports.append([str(port), state, str(service)])
            elif (respon.getlayer(TCP).flags == 0x14):
                closedcount += 1
    timeend = datetime.now()
    return (closedcount, openports, timeend)    

def udpscan(targetIP, ports):
    closedcount = 0
    ofcount = 0
    openports = []
    for port in ports:
        print(".", end="",flush = True)
        respon = sr1(IP(dst = targetIP)/UDP(dport = port), verbose = 0, timeout = .1)
        #s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        if (str(type(respon)) == "<class 'NoneType'>"):
            ofcount += 1
            try:
                service = socket.getservbyport(int(port), 'udp')
                state = "Open"
            except:
                state = "Open | Filtered "
                service = "No Service Found"
            #openports.append([str(port), state, str(service)])  
        elif (str(type(respon)) != "<class 'NoneType'>"):
            if(respon.haslayer(UDP)):
                ofcount += 1
                state = "Open"
                try:
                    service = socket.getservbyport(int(port), 'udp')
                except:
                    service = "No Service Found"
                #openports.append([str(port), state, str(service)])
            elif(respon.haslayer(ICMP)):
                if(int(respon.getlayer(ICMP).type)==3 and int(respon.getlayer(ICMP).code) in [1,2,9,10,13]):
                    ofcount += 1
                    state = "Filtered"
                    try:
                        service = socket.getservbyport(int(port), 'udp')
                    except:
                        service = "No Service Found"
                    #openports.append([str(port), state, str(service)])
                elif(int(respon.getlayer(ICMP).type) == 3 and int(respon.getlayer(ICMP).code) == 3):
                    state = "Closed"
                    closedcount += 1
                    try:
                        service = socket.getservbyport(int(port), 'udp')
                    except:
                        service = "No Service Found"
                    openports.append([str(port), state, str(service)])
    timeend = datetime.now()
    return (ofcount, openports, timeend) #changed ofcount to closed count

def portscanner(targetIP): 
    print( "*" * 40, end="",flush = True)
    timestart = datetime.now()
    print("\n" + "Start time: "+ str(timestart))

    if args.mode[0] == "connect":
        if args.order[0] == "inorder":
            if args.ports[0] == "known":
                closedcount, openports, timeend = cscan(targetIP, knownports)
            else:
                closedcount, openports, timeend = cscan(targetIP, allports)

        else:
            if args.ports[0] == "known":
                ports = randOrder(knownports)
                closedcount, openports, timeend = cscan(targetIP, ports)
            else:
                ports = randOrder(allports)
                closedcount, openports, timeend = cscan(targetIP, ports)
        printout(timeend, timestart, closedcount, openports, args.mode[0])

    elif args.mode[0] == "syn":
        if args.order[0] == "inorder":
            if args.ports[0] == "known":
                closedcount, openports, timeend = synscan(targetIP, knownports)
            else:
                closedcount, openports, timeend = synscan(targetIP, allports)

        else:
            if args.ports[0] == "known":
                ports = randOrder(knownports)
                closedcount, openports, timeend = synscan(targetIP, ports)
            else:
                ports = randOrder(allports)
                closedcount, openports, timeend = synscan(targetIP, ports)
        printout(timeend, timestart, closedcount, openports, args.mode[0])

    elif args.mode[0] == "udp":
        if args.order[0] == "inorder":
            if args.ports[0] == "known":
                closedcount, openports, timeend = udpscan(targetIP, knownports)
            else:
                closedcount, openports, timeend = udpscan(targetIP, allports)

        else: 
            if args.ports[0] == "known":
                ports = randOrder(knownports)
                closedcount, openports, timeend = udpscan(targetIP, ports)
            else:
                ports = randOrder(allports)
                closedcount, openports, timeend = udpscan(targetIP, ports)
        printout(timeend, timestart, closedcount, openports, args.mode[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TCP Port Scanner.')
    parser.add_argument('-mode', choices=['connect','syn','udp'], type= str, nargs=1, help='choose the scanning mode')
    parser.add_argument('-order', choices=['inorder','random'], type= str, nargs=1, help= 'specify the order of port scanning')
    parser.add_argument('-ports', choices=['all','known'], type=str, nargs=1, help= 'decide whether to scan all ports or just the well-known ones')
    parser.add_argument('target', type= str, nargs=1, help= 'target host name or IP address')
    args = parser.parse_args()
    print()
    print("Starting port scan at of following set up: " + "\n" + "Mode= " + args.mode[0] + "\n" + "Order= " + args.order[0] +"\n" + "Port set= "+ args.ports[0]+"\n"+ "Target= " + args.target[0])

    targetIP = checkform(args.target[0])

    status = ping(targetIP)

    if status == "up":
        portscanner(targetIP)
    else:
        print("This host is unreachable." + "\n" + "We are unable to complete a port scan at this time." + "\n")

