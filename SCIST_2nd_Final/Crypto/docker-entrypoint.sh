#!/bin/sh

cd /chal/Baby_Oracle
socat TCP-LISTEN:7000,fork EXEC:"timeout 3600 python3 /chal/Baby_Oracle/server.py" &

cd /chal/Baby_PRNG
socat TCP-LISTEN:7001,fork EXEC:"timeout 3600 python3 /chal/Baby_PRNG/server.py"
