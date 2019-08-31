FROM ubuntu:proxybase
WORKDIR  /home/shlomi/Desktop/proxy/
COPY proxy.py /src/proxy.py
RUN python /src/proxy.py