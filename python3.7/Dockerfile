FROM ubuntu:18.04
#FROM python:3.8.2-slim-buster
RUN apt-get -y update && apt-get -y upgrade
#RUN apt-get install -y build-essential libsasl2-dev python-dev libldap2-dev libssl-dev libaio1 libaio-dev 
RUN apt-get -y install python3.7 python3-pip build-essential libsasl2-dev libldap2-dev libssl-dev libaio1 libaio-dev
RUN python -m pip install --upgrade virtualenv  &&  python -m pip install --upgrade pip

