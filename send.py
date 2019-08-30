# -*- coding:utf-8 -*-

from datetime import datetime
from scapy.all import DNS
from scapy.all import DNSQR
from scapy.all import IP
from scapy.all import UDP
from scapy.all import send
import multiprocessing as mp
import sys


#COUNT = int(sys.argv[1])
#PROCS = int(sys.argv[2])

#Send A DNS query to localhost port 53000. Works, tested wireshark
def sendPacket():
    packet = IP(dst="localhost") / UDP() / DNS(qd=DNSQR(
        qname="google.com", qtype="A"))
    packet[IP].dport = 53000
    send(packet, count=1, verbose=False)


def main():
    ps = [mp.Process(target=sendPacket) for i in xrange(0, PROCS)]
    time1 = datetime.now()
    print time1
    for p in ps:
        p.start()
    for p in ps:
        p.join()
    time2 = datetime.now()
    print len(ps), "x", COUNT, "=", len(ps) * COUNT, "packets.",
    print time2 - time1,
   # print len(ps) * COUNT / (time2 - time1).seconds, "qps"


if __name__ == "__main__":
    main()