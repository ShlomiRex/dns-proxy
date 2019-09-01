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

WAIT4ANSWERS_SECONDS = 2        #time to wait to allow time to gather multiple answers
REQUEST_WAIT_FOR_THREAD = 0.2


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
	if pkt.haslayer(DNS) == False or pkt.haslayer(DNSRR) == False:
		return

	ip_src = pkt[IP].src
	ip_dst = pkt[IP].dst

	port_src = pkt[UDP].sport
	port_dst = pkt[UDP].dport

	#print "dst = " +str(port_dst)

	if port_dst != PORT_SERVER2PROXY:
		return
	
	print "DNS Response"
	print "-----------------------------"
	print_udp_pkt(pkt)

	answers_cache.append(pkt)


#################### Program starts here ####################



def print_console():
    print "[0] <exit>"
    print "[1] Google"
    print "[2] YouTube"

def wait4answers():
	print "[wait4answers] Running..."
	filter = "ip and udp"
	sniff(prn=dns_sniff, filter=filter, timeout=WAIT4ANSWERS_SECONDS)
	print "[wait4answers] Done"

def begin(query_name):
		thread = Thread(target = wait4answers)
		thread.start()
		time.sleep(REQUEST_WAIT_FOR_THREAD)
		dns_req = IP(dst=IP_DNS_SERVER)/UDP(sport=PORT_SERVER2PROXY, dport=PORT_SERVER_DNS)/DNS(rd=1, qd=DNSQR(qname=query_name))
		send(dns_req)
		thread.join()
		print "# of Answers got: " + str(len(answers_cache))
		global answers_cache
		answers_cache = []
		

while True:
    print_console()
    num = input("Enter your function number to run: ")
    if num == 0:
        exit()
    elif num == 1:
		begin("www.google.com")

    elif num == 2:
		begin("www.youtube.com")

    print "\n\n"