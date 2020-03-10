FROM ubuntu:16.04

RUN apt-get update && apt-get -y upgrade && apt-get -y install syslog-ng && \
DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libncursesw5-dev libreadline-dev libssl-dev libgdbm-dev \
libc6-dev libsqlite3-dev libxml2-dev libxslt-dev python python-dev python-setuptools openssh-server python-pip sudo && apt-get clean && \
  pip install --upgrade  &&  pip install --upgrade virtualenv  


