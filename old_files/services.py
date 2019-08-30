#!/usr/bin/env python

DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")
OFFSET = DNS_QUERY_MESSAGE_HEADER.size
###ours###

def find_free_port():# get an unused random port
    s = socket.socket()
    s.bind(('', 0))
    return s.getsockname()[1]

def dnsSend (pkt):
    thread = Thread(pprint.pprint(decode_dns_message(pkt)))
    thread.start()

def dnsRecv (pkt, question):
    thread = Thread(compareCache(pkt,question))
    thread.start()

def compareCache (pkt, Squestions):
    id, misc, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)
    Rquestions, offset1 = decode_question_section(pkt, OFFSET, qdcount)
    if (Squestions == Rquestions):
        return True
    return False




###not ours###

DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

def decode_question_section(message, offset, qdcount): #getthe question
    questions = []

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset


def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            raise StandardError("unknown label encoding")

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        offset += length
