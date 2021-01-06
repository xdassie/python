FROM ubuntu:rolling
#FROM python:3.8.2-slim-buster
RUN apt-get -y update && apt-get -y upgrade
#RUN apt-get install -y build-essential libsasl2-dev python-dev libldap2-dev libssl-dev libaio1 libaio-dev 
RUN apt-get -y install python3-pip build-essential libsasl2-dev libldap2-dev libssl-dev libaio1 libaio-dev
ENV TZ=Africa/Johannesburg
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install  gzip wget git zip software-properties-common curl
RUN python3 -m pip install --upgrade virtualenv  &&  python3 -m pip install --upgrade pip pytest
RUN add-apt-repository ppa:deadsnakes/ppa && apt install -y python3.7
