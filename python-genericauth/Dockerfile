FROM quay.io/xdassie/python:latest
ARG DIRLIST="/app/"
RUN mkdir -p ${DIRLIST}  && \ 
    chgrp -Rf root ${DIRLIST} && chmod -Rf g+w  ${DIRLIST}
#FROM python:3
COPY requirements.txt ./
#COPY ldap.conf /etc/ldap/ldap.conf

RUN python -m pip  install -r requirements.txt
RUN apt-get -y remove build-essential && apt-get -y autoremove 
RUN apt-get -y install ldap-utils


EXPOSE 8080

CMD ["python", "/app/server.py"]
COPY ./app /app
