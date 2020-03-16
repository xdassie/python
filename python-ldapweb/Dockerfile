FROM quay.io/xdassie/python:latest
#FROM python:3
COPY requirements.txt ./

RUN pip install --upgrade pip && pip  install -r requirements.txt
RUN apt-get -y remove build-essential && apt-get -y autoremove
