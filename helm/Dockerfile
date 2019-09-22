FROM xdassie/helm:latest
COPY pythondemo ./pythondemo
RUN helm --debug --host=localhost:44134 template pythondemo
