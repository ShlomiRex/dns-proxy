#!/usr/bin/env python

from threading import Thread
from scapy.all import *
import time

#################### Constants ####################

IP_LOCALHOST = "127.0.0.1"
IP_DNS_SERVER = "1.1.1.1"

PORT_SERVER2PROXY = 53000   
PORT_SERVER_DNS = 53

DEBUG_CACHE = False

WAIT4ANSWERS_SECONDS = 4        #time to wait to allow time to gather multiple answers
REQUEST_WAIT_FOR_THREAD = 0.2


#################### Global Variables1e ####################
answers_cache = []
cache = {}

def print_udp_pkt(pkt):#
	ip_src = pkt[IP].src
	ip_dst = pkt[IP].dst
	port_src = pkt[UDP].sport
	port_dst = pkt[UDP].dport

	print str(ip_src) + ":" + str(port_src) + " -> " + str(ip_dst) + ":" + str(port_dst)

def dns_sniff(pkt):
	print_udp_pkt(pkt)

	answers_cache.append(pkt)

def statusDoc():
	print "[0] worked well"
	print "[1] conflict"
	print "[2] no masseges returns"


def print_console():
	print "[0] <exit>"
	print "[1] Google"
	print "[2] YouTube"
	print "[3] Amit Dvir"

#################### Program starts here ####################

def wait4answers():
	print "[wait4answers] Running..."
	filter = "udp and port 53 and dst port 53000"
	sniff(prn=dns_sniff, filter=filter, timeout=WAIT4ANSWERS_SECONDS)
	print "[wait4answers] Done"

def hasCache():
	ans = cache.get(answers_cache[0][DNS].qd[0].qname) #compare from the cache
	for i in range (len(answers_cache)):			 #for each pkts:
		#print answers_cache[i][DNS].show()
		match = False
		pktAns=[]
		for x in range(answers_cache[i][DNS].ancount): #compare from other pkt to cache
			if (answers_cache[i][DNSRR][x].rdata in ans):
				#print "match"
				match = True
				pktAns.append(answers_cache[i][DNSRR][x].rdata)
		if(match):										#return the first matchs pkt
			return 0, pktAns
	return 1, []										#no pkt matchd

def noCache():
	ans = []
	for x in range(answers_cache[0][DNS].ancount): 	#compare from the first pkt
		ans.append(answers_cache[0][DNSRR][x].rdata)
	for i in range (1, len(answers_cache)):			 #for each other pkts:
		print ans
		print answers_cache[i][DNS].show()
		match = False
		pktAns=[]
		for x in range(answers_cache[i][DNS].ancount): #compare from other pkt to first pkt
			if (answers_cache[i][DNSRR][x].rdata in ans):
				print "match"
				match = True
				pktAns.append(answers_cache[i][DNSRR][x].rdata)
		if(not match):
			return 1, []
		print pktAns
		new_ans = []
		for x in range(len(ans)):					#compare from first pkt to other pkt
			if (ans[x] in pktAns):
				print "append"
				new_ans.append(ans[x])
				#ans.pop(x)
		ans = new_ans
		if len(ans)==0:
			return 1, []
	return 0, ans

def analyze():
	if(len(answers_cache)>0):
		if (not cache.get(answers_cache[0][DNS].qd[0].qname) is None) and (DEBUG_CACHE):
			status, ans = hasCache()
			if status == 0:
				return status, ans
		#no cache or not matchs to cache
		status, ans = noCache()
		if status == 0:
			cache[answers_cache[0][DNS].qd[0].qname] = ans
		return status, ans
	else:
		return 2, []

def begin(query_name):
		global answers_cache
		thread = Thread(target = wait4answers)
		thread.start()
		time.sleep(REQUEST_WAIT_FOR_THREAD)
		dns_req = IP(dst=IP_DNS_SERVER)/UDP(sport=PORT_SERVER2PROXY, dport=PORT_SERVER_DNS)/DNS(rd=1, qd=DNSQR(qname=query_name))
		send(dns_req)
		thread.join()
		print "# of Answers got: " + str(len(answers_cache))+"\n\n"

		#print "analyze answers:"
		status, ans = analyze()
		statusDoc()
				
		
		answers_cache = []
		return status, ans
		

while True:
	print_console()
	num = input("Enter your function number to run: ")
	status = 0
	ans = []

	if num == 0:
		exit()
	elif num == 1:
		status, ans = begin("www.google.com")
	elif num == 2:
		status, ans = begin("www.youtube.com")
	elif num == 3:
		status, ans = begin("www.amitdvir.com")
	print "Status:"
	print status
	print "Answers:"
	print ans