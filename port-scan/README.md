# PORT_SCANNER.py documentation file:

### Descriptions 
The following functions are included within port_scanner.py:
1. checkform(target)
    * This function checks the argument "target" to see if it is a match for the formatting of an IP address. If there is an error, the function will tell you that the formatting of your specified target is incorrect.  
2. ping(targetIP)
    * This function pings the host, using the targetIP obtained, to test if it is alive and reachable. It returns the value status, which is to tell you the host is up or unreachable. 
    * Sources used: (for the verbose= 0 optional argument to supress stdout printing to terminal) [stackoverflow](https://stackoverflow.com/questions/15377150/how-can-i-call-the-send-function-without-getting-output)
3. randOrder(portset)
    * This function takes the specified port set and takes a random sample without replacement to create a random order of the port checks.  
4. printout(timeend, timestart, closedcount, openports, mode) 
    * This function formats the final print sections of the scanner based on the spcified mode. The function is provided with the time the scanning started and ended, along with a list of the open ports and a list of counted ports. 
5. getbanner(sock, targetIP, port)
    * This function sends an HTTP get request to the target IP and the port we are looking at in order to obtain the banner after the full TCP handshake is completed. 
    * This function also trims the banner and removes the new line characters. 
    * #source:[medium] (https://medium.com/geekculture/implementing-http-from-socket-89d20a1f8f43)
6. cscan(targetIP, ports)
    * This method makes a full connection to each port. If the connection is established the port is open. In this method, the scanner should capture any initial information (e.g., banner) the server sends back. 
    * This function completes a full TCP handshake then connects with the socket.
    source for this [python](https://docs.python.org/3/library/socket.html#socket.create_connection)
    * A timeout was needed for the socket because the program would hang. 
    checked for settimeout: [python] (https://docs.python.org/3/library/socket.html#socket.socket.settimeout)
    * The service is obtained by getservbyport(). [nmapConnectScan](https://nmap.org/book/scan-methods-connect-scan.html)
7. synscan(targetIP, ports)
    * This sends a start connection signal (SYN) and end the connection if the host responds (with SYN/ACK), without fully connecting.
    * The first if statement checks for a nonetype class, this is to mark filtered ports if you have no response or ICMP unreachable error:[techtarget] (https://www.techtarget.com/searchnetworking/definition/SYN-scanning#:~:text=TCP%20SYN%20scan&text=It%20works%20by%20sending%20a,it%20indicates%20a%20filtered%20state.) 
    It is also largely commented out as it convolutes the print out. 
    * If the response received has certain flags, thats how you differ between open or closed states. 
8. udpscan(targetIP, ports)
    * This sends a UDP packet to each port. If there is no response, the port is likely open or filtered. If an ICMP port unreachable error message is returned, the port is closed. 
    * info on open/filtered/closed: [nmap](https://nmap.org/book/scan-methods-udp-scan.html#:~:text=Open%20and%20filtered%20ports%20rarely,an%20ICMP%20port%20unreachable%20error.)
    * in the first if statement we are determining open | filtered ports, it is commented because otherwise all of them get listed as open or open|filtered it's easier to display the closed ports, everything else is assumed open or filtered
    * to avoid over complicated outputs, This function returns CLOSED ports only. so the ports which returned the ICMP dest unreachable error.
9. portscanner(targetIP)
    * This runs some of the aformentioned functions based upon the mode, order, and port set specified. it is set up for all combinations of the sets we can run as options. 


Finally, the end of the program is the main program. The first section parses the command line arguments into useable pieces. [pythondocumentation](https://docs.python.org/3/library/argparse.html)
It then checks IP form and pings the targetIP. Then if that ping reports an "up" status, we will run the portscanner() function. Otherwise, a message will print that the host was unreachable. 



### INSTRUCTIONS 
Python3 port_scanner.py -mode connect -order inorder -ports known target
