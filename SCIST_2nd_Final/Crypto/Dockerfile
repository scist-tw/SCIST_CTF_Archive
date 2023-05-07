FROM alpine

RUN apk add --no-cache python3 py3-pip socat

RUN pip3 install --upgrade pip && pip3 install --upgrade pycryptodome

RUN mkdir -p /chal/Baby_Oracle /chal/Baby_PRNG
WORKDIR /chal

COPY ./Baby_Oracle/src /chal/Baby_Oracle
COPY ./Baby_PRNG/src /chal/Baby_PRNG
COPY ./docker-entrypoint.sh /chal
RUN chmod +x /chal/docker-entrypoint.sh

CMD ["/chal/docker-entrypoint.sh"]