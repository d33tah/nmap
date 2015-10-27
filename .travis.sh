#!/bin/bash

set -e

pip install twisted
twistd -n web &
SERV_PID=$!
mkdir /tmp/n
./configure $SSL_FLAG $LUA_FLAG --prefix=/tmp/n
make
make check
make install
/tmp/n/bin/nmap -A localhost
kill $SERV_PID
