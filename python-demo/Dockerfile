#FROM ubuntu:20.04
FROM ubuntu:rolling
#FROM python:3.8.2-slim-buster
RUN apt-get -y update && apt-get -y upgrade
#RUN apt-get install -y build-essential libsasl2-dev python-dev libldap2-dev libssl-dev libaio1 libaio-dev 
RUN apt-get -y install python-dev-is-python3 python3-pip build-essential libsasl2-dev libldap2-dev libssl-dev libaio1 libaio-dev
RUN python -m pip install --upgrade virtualenv  &&  python -m pip install --upgrade pip
#apt-get -y install syslog-ng && \
#DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libncursesw5-dev libreadline-dev libssl-dev libgdbm-dev \
#libc6-dev libsqlite3-dev libxml2-dev libxslt-dev python python-dev python-setuptools openssh-server python-pip sudo && apt-get clean && \
#  pip install --upgrade  &&  pip install --upgrade virtualenv  && pip install --upgrade pip


