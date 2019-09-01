from scapy.all import DNS, DNSQR, IP, sr1, UDP, send

ip_src = "127.0.0.1"
#server = "127.0.0.1"
#server = "1.1.1.1"
server = "8.8.8.8"
#server = "172.17.0.2"

sport = 53000
dport = 53

def google():
    dns_req = IP(dst=server)/UDP(sport=sport, dport=dport)/DNS(rd=1, qd=DNSQR(qname='www.google.com'))
    send(dns_req)
def youtube():
    dns_req = IP(dst=server)/UDP(sport=sport, dport=dport)/DNS(rd=1, qd=DNSQR(qname='www.youtube.com'))
    send(dns_req)
#answer = sr1(dns_req, verbose=0)
#print(answer[DNS].summary())