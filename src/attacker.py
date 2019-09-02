from scapy.all import *
import time

rrname = "www.google.com"
evil_dest = "6.6.6.6"
dst = "172.17.0.2"
src = "1.1.1.1"
rrname = "www.google.com"

google_real_ip = "216.58.198.164"
amitdvir_real_ip = "160.153.129.23"

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

#status = 0
#ans = ['216.58.206.100']
def test1():
    pkt1 = dns_res
    pkt1[DNS].ancount=2
    pkt1[DNS].an = DNSRR(rrname=rrname,rdata="1.1.1.1")/DNSRR(rrname=rrname, rdata=google_real_ip)
    send(pkt1)



#pkt1: 1.1.1.1, 2.2.2.2
#pkt2: 2.2.2.2, 3.3.3.3
#status = 1
#ans = []
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

#2 Pacekts, malicious
#status = 1
#ans = []
def amit_test1():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=rrname,rdata="1.1.1.1")/DNSRR(rrname=rrname, rdata="2.2.2.2")
    send(pkt1)


#2 Pacekt, 1 malicous 1 real
#status = 0
#ans = ["amitdvir_real_ip"]
def amit_test2():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=rrname,rdata=amitdvir_real_ip)/DNSRR(rrname=rrname, rdata="2.2.2.2")
    send(pkt1)


#same as amit_test2()
#but the DNSRR is switched 
def amit_test3():
    pkt1 = IP(src=src, dst=dst)/UDP(sport=53, dport=53000)/DNS(id=0,
        aa=1,
        rd=1,
        qd=DNSQR(qname=rrname),
        qr=1,
        qdcount=1,
        ancount=2)
    pkt1[DNS].an = DNSRR(rrname=rrname, rdata="2.2.2.2")/DNSRR(rrname=rrname,rdata=amitdvir_real_ip)
    send(pkt1)


#send(dns_res)
while True:
    amit_test2() #Worked Well
    time.sleep(0.5)