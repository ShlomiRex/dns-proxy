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

DEBUG_CLIENT2PROXY = False
DEBUG_SERVER2PROXY = True

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
		if pkt.haslayer(DNS) == False or pkt.haslayer(DNSQR) == False:
			return

		if pkt[DNS].qr == "1":
			return
		
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst

		port_src = pkt[UDP].sport #Usually random number, not useful
		port_dst = pkt[UDP].dport

		if port_dst != PORT_CLIENT2PROXY:
			return

		if ip_src != IP_LOCALHOST:
			return

		#Skip double packets (leave and enter)
		#See: https://stackoverflow.com/questions/52232080/scapy-sniff-the-packet-multiple-times
		if self.last_dns_packet == pkt:
			return

		self.last_dns_packet = pkt

		if pkt.getlayer(DNS).qr == 0:
			#Request
			self.prints("[Client2Proxy] DNS Request")
			self.prints("-----------------------------")
			pass
		elif pkt.getlayer(DNS).qr == 1:
			#Response
			self.prints("[Client2Proxy] DNS Response")
			self.prints("-----------------------------")
			pass

		#print_udp_pkt(pkt)
		#Type your code here

		#print pkt[DNSQR].summary()
		qname = pkt[DNSQR].qname
		rd = pkt[DNS].rd
		qr = pkt[DNS].qr

		self.prints("qr = " + str(qr))
		self.prints("rd = " + str(rd))

		#print "rd = " + str(rd)

		dns_req = IP(dst=IP_DNS_SERVER, src=IP_LOCALHOST)/UDP(sport=PORT_SERVER2PROXY, dport=53)/DNS(rd=1, qd=DNSQR(qname=qname))
		#print dns_req[UDP].show()
		send(dns_req, verbose=False)


	def print_udp_pkt(pkt):#
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		port_src = pkt[UDP].sport
		port_dst = pkt[UDP].dport

		self.prints(str(ip_src) + ":" + str(port_src) + " -> " + str(ip_dst) + ":" + str(port_dst))

	def prints(self, str):
		if DEBUG_CLIENT2PROXY:
			print str




#Proxy <---> Server
#Server <---> Proxy
class Server2Proxy(Thread):
	last_dns_packet = None
	def __init__(self):
		super(Server2Proxy, self).__init__()

	def run(self):
		print "[Server2Proxy] Running..."

		#filter = "ip dst host " + IP_LOCALHOST + " and dst port " + str(PORT_CLIENT2PROXY) + " and udp"
		filter = "ip dst host " + IP_LOCALHOST + " and udp and src host " + IP_DNS_SERVER
		#filter = "ip and udp"
		sniff(prn= self.dns_sniff , filter=filter)

		print "[Server2Proxy] Done"
	def dns_sniff(self, pkt):

		#Only DNS in UDP protocol
		if pkt.haslayer(DNS) == False or pkt.haslayer(DNSRR) == False:
			return

		if pkt[DNS].qr == "0":
			return

		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst

		port_src = pkt[UDP].sport #Usually random number, not useful
		port_dst = pkt[UDP].dport

		if port_dst != PORT_SERVER2PROXY:
			return

		#Skip double packets (leave and enter)
		#See: https://stackoverflow.com/questions/52232080/scapy-sniff-the-packet-multiple-times
		if self.last_dns_packet == pkt:
			returnIP_LOCALHOST

		self.last_dns_packet = pkt

		if pkt.getlayer(DNS).qr == 0:
			#Request
			self.prints("")
			self.prints("[Server2Proxy] DNS Request")
			self.prints("-----------------------------")
			pass
		elif pkt.getlayer(DNS).qr == 1:
			#Response
			self.prints("[Server2Proxy] DNS Response")
			self.prints("-----------------------------")
			pass

		self.print_udp_pkt(pkt)
		#Type your code here
		qname = pkt[DNSQR].qname
		rd = pkt[DNS].rd
		rrname = pkt[DNSRR].rrname
		qr = pkt[DNS].qr

		'''
		self.prints("rd = " + str(rd))
		self.prints("qname = " + qname)
		self.prints("rrname = " + rrname)
		self.prints("qr = " + str(qr))
		'''

		

		dns_res = IP(dst=IP_LOCALHOST, src=IP_LOCALHOST)/UDP(sport=PORT_SERVER2PROXY, dport=53)/pkt[DNS]
		
		#dns_res = pkt
		#dns_res[IP].src = IP_LOCALHOST
		#dns_res[IP].dst = IP_LOCALHOST
		#dns_res[UDP].sport = PORT_SERVER2PROXY
		#dns_res[UDP].dport = 53

		'''
		self.prints("\n\n\n\n\n")
		#self.prints(dns_res[DNSRR].show())
		self.prints(dns_res[IP].show())
		self.prints("\n\n\n\n\n")
		'''

		#self.prints(dns_res[IP].show())
		#self.print_udp_pkt(dns_res)
		send(dns_res, verbose=False)


	
	def prints(self, str):
		if DEBUG_SERVER2PROXY:
			print str

	def print_udp_pkt(self, pkt):#
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		port_src = pkt[UDP].sport
		port_dst = pkt[UDP].dport

		self.prints(str(ip_src) + ":" + str(port_src) + " -> " + str(ip_dst) + ":" + str(port_dst))

# Main Thread
class Proxy(Thread):
	def __init__(self):
		super(Proxy, self).__init__()

	def run(self):
		try:
			print "[Proxy] Running..."

			self.c2p = Client2Proxy()
			self.p2s = Server2Proxy()

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