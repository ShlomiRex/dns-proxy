from scapy.all import *


def sniffer(pkt):
    print pkt.show()


sniff(prn=sniffer, filter="udp and ip and dst port 53000")
