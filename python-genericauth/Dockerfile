FROM quay.io/xdassie/python:latest
ARG DIRLIST="/app /app/cacerts"
RUN mkdir -p ${DIRLIST}  && \ 
    chgrp -Rf root ${DIRLIST} && chmod -Rf g+wrx  ${DIRLIST} 
    
COPY requirements.txt ./

RUN python -m pip  install -r requirements.txt
RUN apt-get -y remove build-essential && apt-get -y autoremove 
RUN apt-get -y install ldap-utils redis

EXPOSE 8080

CMD ["python", "/app/server.py"]
COPY ./app /app

