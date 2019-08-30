#!/usr/bin/env python

from threading import Thread
from scapy.all import *

'''
COUNTSEND = 3
DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")
OFFSET = DNS_QUERY_MESSAGE_HEADER.size
'''

IP_LOCALHOST = "10.0.0.2"
IP_DNS_SERVER = "1.1.1.1"

PORT_CLIENT2PROXY = 53000
PORT_PROXY2SERVER = 53000




def decode_dns_message(message):

    id, misc, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)

    qr = (misc & 0x8000) != 0
    opcode = (misc & 0x7800) >> 11
    aa = (misc & 0x0400) != 0
    tc = (misc & 0x200) != 0
    rd = (misc & 0x100) != 0
    ra = (misc & 0x80) != 0
    z = (misc & 0x70) >> 4
    rcode = misc & 0xF

    questions, offset1 = decode_question_section(message, OFFSET, qdcount)

    result = {"id": id,
              "is_response": qr,
              "opcode": opcode,
              "is_authoritative": aa,
              "is_truncated": tc,
              "recursion_desired": rd,
              "recursion_available": ra,
              "reserved": z,
              "response_code": rcode,
              "question_count": qdcount,
              "answer_count": ancount,
              "authority_count": nscount,
              "additional_count": arcount,
              "questions": questions}


    #started here
    if (result.qr == 0):
        oldPort = rcvPkt[IP].sport
        sendPort = find_free_port()
        rcvPkt[IP].sport = sendPort

        send(rcvPkt, count=COUNTSEND, verbose=False)


        

    return result


#Client <---> Proxy
#Proxy <---> Client
class Client2Proxy(Thread):
    def __init__(self, host, port):
        super(Client2Proxy, self).__init__()
        self.port = port
        self.host = host

    def run(self):
        print "[Client2Proxy] Running..."
        sniff(iface="lo", prn= self.dns_sniff )
        print "[Client2Proxy] Done"

    def dns_sniff(self, pkt):
        if IP not in pkt:
            return
        
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        #if ip_src != "10.0.0.2" and ip_dst != "10.0.0.2":
            #return

        #Only DNS in UDP protocol
        if pkt.haslayer(UDP) == False or pkt.haslayer(DNS) == False:
            return

        port_src = pkt[UDP].sport
        port_dst = pkt[UDP].dport

        if port_src == 53000 or port_dst == 53000:
            self.print_udp_pkt(pkt)
            print pkt[DNS]

        if pkt.getlayer(DNS).qr == 0:
            #print "DNS Query:"
            pass

    def print_udp_pkt(self, pkt):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            port_src = pkt[UDP].sport
            port_dst = pkt[UDP].dport

            print str(ip_src) + ":" + str(port_src) + " -> " + str(ip_dst) + ":" + str(port_dst)




#Proxy <---> Server
#Server <---> Proxy
class Proxy2Server(Thread):
    def __init__(self, host, port, server_ip):
		super(Proxy2Server, self).__init__()
		self.port = port
		self.host = host
		self.server_ip = server_ip

    def run(self):
		print "[Proxy2Server] Running..."


		print "[Proxy2Server] Done"


# Main Thread
class Proxy(Thread):
    def __init__(self):
        super(Proxy, self).__init__()

    def run(self):
		try:
			print "[Proxy] Running..."

			self.c2p = Client2Proxy(IP_LOCALHOST, PORT_CLIENT2PROXY)
			self.p2s = Proxy2Server(IP_LOCALHOST, PORT_PROXY2SERVER, IP_DNS_SERVER)

			#self.c2p.daemon = True
			#self.p2s.daemon = True

			self.c2p.start()
			self.p2s.start()

			self.c2p.join()
			self.p2s.join()

			print "[Proxy] Done"

		except KeyboardInterrupt:
			print('Interrupted')
		try:
			sys.exit(0)
		except SystemExit:
			os._exit(0)




master_server = Proxy()
master_server.start()

'''
print "Sniffing..."
#sniff(filter = 'dst port 53000', prn=dnsSend)
sniff(iface="lo", prn=dns_sniff) #choosing local interface is important, because if we choose destination port ot be localhost, packets wont show up (tested)
print "Done sniffing"
'''