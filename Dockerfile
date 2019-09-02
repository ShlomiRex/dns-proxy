FROM ehlers/scapy

EXPOSE 53000

RUN apt-get update 
RUN apt-get install python -y
RUN apt-get install python-pip -y
RUN pip install scapy
