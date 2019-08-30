from scapy.all import DNS, DNSQR, IP, sr1, UDP, send

for i in range(0,10):

    dns_req = IP(dst='10.0.0.2')/UDP(dport=53000)/DNS(rd=1, qd=DNSQR(qname='www.google.com'))
    dns_req.src = "10.0.0.2"
    send(dns_req)
    #answer = sr1(dns_req, verbose=0)
    #print(answer[DNS].summary())