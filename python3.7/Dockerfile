FROM quay.io/xdassie/python:latest
RUN apt-get -y update && apt-get -y install python3.7 2>&1 
RUN update-alternatives --list python
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.7 1

