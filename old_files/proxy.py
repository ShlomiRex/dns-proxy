#!/usr/bin/env python

import pprint
import socket
import struct
from threading import Thread
from scapy.all import *
import ./services

COUNTSEND = 3
DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")
OFFSET = DNS_QUERY_MESSAGE_HEADER.size




def recivePKTs(question, port):
    #TODO get from Scache









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





s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = ''
port = 53000
size = 512
s.bind((host, port))
while True: 
    #TODO choose best method
    sniff(filter = 'dst port 53000', prn=dnsSend)
    data, addr = s.recvfrom(size)
    thread = Thread(pprint.pprint(decode_dns_message(data)))
    thread.start()