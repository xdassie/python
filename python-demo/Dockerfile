FROM ubuntu:18.10

RUN apt-get -y update && apt-get install -y libsasl2-dev python-dev libldap2-dev libssl-dev libaio1 libaio-dev  && apt-get -y upgrade &&  \
apt-get -y install syslog-ng && \
DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libncursesw5-dev libreadline-dev libssl-dev libgdbm-dev \
libc6-dev libsqlite3-dev libxml2-dev libxslt-dev python python-dev python-setuptools openssh-server python-pip sudo && apt-get clean && \
  pip install --upgrade  &&  pip install --upgrade virtualenv  && pip install --upgrade pip


