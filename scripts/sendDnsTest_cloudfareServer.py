from scapy.all import DNS, DNSQR, IP, sr1, UDP

dns_req = IP(dst='1.1.1.1')/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='www.google.com'))
answer = sr1(dns_req, verbose=0)
print(answer[DNS].summary())