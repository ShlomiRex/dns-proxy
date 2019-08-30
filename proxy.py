#!/usr/bin/env python

import struct
from threading import Thread
from scapy.all import *


IP_LOCALHOST = "10.0.0.2" #Your pc local ip
IP_DNS_SERVER = "10.0.0.151" #My own dns server at home (for you it's usually the gateway)

                              #src port of client is random
                              #dst port of client is 53 at default
PORT_CLIENT2PROXY = 53000     #Port of Proxy that listens to client
PORT_SERVER2PROXY = 53001     #Port of proxy that listens to server's answers

#Client <---> Proxy
#Proxy <---> Client
class Client2Proxy(Thread):
    last_dns_packet = None
    def __init__(self):
        super(Client2Proxy, self).__init__()

    def run(self):
        print "[Client2Proxy] Running..."
        #filter = "ip dst host " + IP_LOCALHOST + " and dst port " + str(PORT_CLIENT2PROXY) + " and udp"
        filter = "ip dst host " + IP_LOCALHOST + " and udp and src host " + IP_LOCALHOST
        #filter = "ip and udp"
        sniff(iface = "lo", prn= self.dns_sniff , filter=filter)
        print "[Client2Proxy] Done"

    def dns_sniff(self, pkt):
        #Only DNS in UDP protocol
        if pkt.haslayer(DNS) == False:
            return
        
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        port_src = pkt[UDP].sport #Usually random number, not useful
        port_dst = pkt[UDP].dport

        if ip_src != IP_LOCALHOST:
            return

        #Skip double packets (leave and enter)
        #See: https://stackoverflow.com/questions/52232080/scapy-sniff-the-packet-multiple-times
        if self.last_dns_packet == pkt:
            return

        self.last_dns_packet = pkt

        if pkt.getlayer(DNS).qr == 0:
            #Request
            print "[Client2Proxy] DNS Request"
            print "-----------------------------"
            pass
        elif pkt.getlayer(DNS).qr == 1:
            #Response
            print "[Client2Proxy] DNS Response"
            print "-----------------------------"
            pass

        self.print_udp_pkt(pkt)
        #Type your code here

        #print pkt[DNSQR].summary()
        qname = pkt[DNSQR].qname
        rd = pkt[DNS].rd
        #print "rd = " + str(rd)
        
        dns_req = IP(dst=IP_DNS_SERVER, src=IP_LOCALHOST)/UDP(sport=PORT_CLIENT2PROXY, dport=53)/DNS(rd=1, qd=DNSQR(qname=qname))
        #print dns_req[UDP].show()
        send(dns_req)


    def print_udp_pkt(self, pkt):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            port_src = pkt[UDP].sport
            port_dst = pkt[UDP].dport

            print str(ip_src) + ":" + str(port_src) + " -> " + str(ip_dst) + ":" + str(port_dst)




#Proxy <---> Server
#Server <---> Proxy
class Proxy2Server(Thread):
    def __init__(self):
		super(Proxy2Server, self).__init__()

    def run(self):
		print "[Proxy2Server] Running..."


		print "[Proxy2Server] Done"


# Main Thread
class Proxy(Thread):
    def __init__(self):
        super(Proxy, self).__init__()

    def run(self):
		try:
			print "[Proxy] Running..."

			self.c2p = Client2Proxy()
			self.p2s = Proxy2Server()

			#self.c2p.daemon = True
			#self.p2s.daemon = True

			self.c2p.start()
			self.p2s.start()

			self.c2p.join()
			self.p2s.join()

			print "[Proxy] Done"

		except KeyboardInterrupt:
			print('Interrupted')
		try:
			sys.exit(0)
		except SystemExit:
			os._exit(0)




Proxy().start()