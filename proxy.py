#!/usr/bin/env python

from threading import Thread
from scapy.all import *
import time

#################### Constants ####################

IP_LOCALHOST = "127.0.0.1"
IP_DNS_SERVER = "1.1.1.1"

PORT_SERVER2PROXY = 53000   
PORT_SERVER_DNS = 53

DEBUG_SERVER2PROXY = True
DEBUG_WAIT4ANSWERS = False

WAIT4ANSWERS_SECONDS = 5        #time to wait to allow time to gather multiple answers
REQUEST_WAIT_FOR_THREAD = 0.1


#################### Global Variables1e ####################
'''
answers_time = 0   # If it goes above WAIT4ANSWERS_MS then stop gathering answers
answers_cache = []
filterPkt = "udp and port 53 and dst port 53000"
packets=[]
def addAnswer(pkt):
	packets.append(pkt)
def getAnswers():
	sniff(prn = addAnswer, timeout = WAIT4ANSWERS_MS, filter = "filterPkt")
	for (pkt in packets):
'''
answers_cache = []

def print_udp_pkt(pkt):#
	ip_src = pkt[IP].src
	ip_dst = pkt[IP].dst
	port_src = pkt[UDP].sport
	port_dst = pkt[UDP].dport

	print str(ip_src) + ":" + str(port_src) + " -> " + str(ip_dst) + ":" + str(port_dst)
	print "\n"

def dns_sniff(pkt):
	print_udp_pkt(pkt)


#################### Program starts here ####################



def print_console():
	print "[0] <exit>"
	print "[1] Google"
	print "[2] YouTube"

def wait4answers():
	print "[wait4answers] Running..."
	filter = "udp and port 53 and dst port 53000"
	print "DNS Response"
	print "-----------------------------"
	sniff(prn=dns_sniff, filter=filter, timeout=WAIT4ANSWERS_SECONDS)
	print "[wait4answers] Done"


while True:
	#print_console()
	getAnswers()
	print "\n\n"
	num = input("Enter your function number to run: ")

    if num == 0:
        exit()
    elif num == 1:
		thread = Thread(target = wait4answers)

		thread.start()
		time.sleep(REQUEST_WAIT_FOR_THREAD)
		dns_req = IP(dst=IP_DNS_SERVER)/UDP(sport=PORT_SERVER2PROXY, dport=PORT_SERVER_DNS)/DNS(rd=1, qd=DNSQR(qname='www.google.com'))
		send(dns_req)
		thread.join()

    elif num == 2:
		thread = Thread(target = wait4answers)

		thread.start()
		time.sleep(REQUEST_WAIT_FOR_THREAD)
		dns_req = IP(dst=IP_DNS_SERVER)/UDP(sport=PORT_SERVER2PROXY, dport=PORT_SERVER_DNS)/DNS(rd=1, qd=DNSQR(qname='www.youtube.com'))
		send(dns_req)
		thread.join()

    print "\n\n"


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


answers_time = 0   # If it goes above WAIT4ANSWERS_MS then stop gathering answers
answers_cache = []
filterPkt = "udp and port 53 and dst port 53000"
packets=[]
def addAnswer(pkt):
	packets.append(pkt)
def getAnswers():
	pppp = sniff(prn = addAnswer, timeout = 3)
	print type(pppp)
