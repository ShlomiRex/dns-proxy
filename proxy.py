#!/usr/bin/env python

import struct
from threading import Thread
from scapy.all import *

#################### Constants ####################

IP_LOCALHOST = "127.0.0.1"
IP_DNS_SERVER = "1.1.1.1"

PORT_SERVER2PROXY = 53000     #Port of proxy that listens to server's answers

DEBUG_CLIENT2PROXY = False
DEBUG_SERVER2PROXY = True
DEBUG_WAIT4ANSWERS = False

WAIT4ANSWERS_MS = 1500        #miliseconds to wait to allow time to gather multiple answers


#################### Global Variables1e ####################

answers_time = 0   # If it goes above WAIT4ANSWERS_MS then stop gathering answers
answers_cache = []

class Server2Proxy(Thread):
	last_dns_packet = None
	def __init__(self):
		super(Server2Proxy, self).__init__()

	def run(self):
		self.prints("[Server2Proxy] Running...")

		#filter = "ip dst host " + IP_LOCALHOST + " and dst port " + str(PORT_CLIENT2PROXY) + " and udp"
		#filter = "udp and src host " + IP_DNS_SERVER
		filter = "ip and udp"
		sniff(prn= self.dns_sniff, filter=filter)

		self.prints("[Server2Proxy] Done")
	def dns_sniff(self, pkt):
		if pkt.haslayer(DNS) == False or pkt.haslayer(DNSRR) == False:
			return

		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst

		port_src = pkt[UDP].sport
		port_dst = pkt[UDP].dport

		if port_dst != PORT_SERVER2PROXY:
			return

		#Skip double packets (leave and enter)
		#See: https://stackoverflow.com/questions/52232080/scapy-sniff-the-packet-multiple-times
		if self.last_dns_packet == pkt:
			returnIP_LOCALHOST

		self.last_dns_packet = pkt

		self.prints("[Server2Proxy] DNS Response")
		self.prints("-----------------------------")
		self.print_udp_pkt(pkt)

	def prints(self, str):
		if DEBUG_SERVER2PROXY:
			print str

	def print_udp_pkt(self, pkt):#
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		port_src = pkt[UDP].sport
		port_dst = pkt[UDP].dport

		self.prints(str(ip_src) + ":" + str(port_src) + " -> " + str(ip_dst) + ":" + str(port_dst))
		self.prints("\n")

#################### Program starts here ####################

print "[Proxy] Running..."
p2s = Server2Proxy()
p2s.start()
p2s.join()
print "[Proxy] Done"

'''
class Wait4Answers(Thread):
	def __init__(self):
		super(Wait4Answers, self).__init__()

	def run(self):
		self.prints("[Wait4Answers] Running...")
		#filter = "ip dst host " + IP_LOCALHOST + " and dst port " + str(PORT_CLIENT2PROXY) + " and udp"
		filter = "ip dst host " + IP_LOCALHOST + " and udp and src host " + IP_DNS_SERVER
		#filter = "ip and udp"
		sniff(prn= self.dns_sniff , filter=filter)
		self.prints("[Wait4Answers] Done")
	
	def prints(self, str):
		if DEBUG_WAIT4ANSWERS:
			print str
	
	def print_udp_pkt(pkt):#
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		port_src = pkt[UDP].sport
		port_dst = pkt[UDP].dport

		self.prints(str(ip_src) + ":" + str(port_src) + " -> " + str(ip_dst) + ":" + str(port_dst))
'''