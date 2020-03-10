#FROM quay.io/xdassie/python:latest
FROM python:3
COPY requirements.txt ./

RUN apt-get -y update && apt-get -y upgrade && apt-get install -y libsasl2-dev python-dev libldap2-dev libssl-dev libaio1 libaio-dev

RUN pip install --upgrade pip && pip  install -r requirements.txt
