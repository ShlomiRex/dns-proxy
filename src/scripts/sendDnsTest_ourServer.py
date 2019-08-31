from scapy.all import DNS, DNSQR, IP, sr1, UDP, send

def google():
    dns_req = IP(dst='10.0.0.2', src="10.0.0.2")/UDP(dport=53000)/DNS(rd=1, qd=DNSQR(qname='www.google.com'))
    send(dns_req)
def youtube():
    dns_req = IP(dst='10.0.0.2', src="10.0.0.2")/UDP(dport=53000)/DNS(rd=1, qd=DNSQR(qname='www.youtube.com'))
    send(dns_req)
#answer = sr1(dns_req, verbose=0)
#print(answer[DNS].summary())