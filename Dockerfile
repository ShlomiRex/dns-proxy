FROM ehlers/scapy

RUN apt-get update 
RUN apt-get install python -y
RUN apt-get install python-pip -y
RUN pip install scapy
RUN apt-get install tcpdump
