#!/bin/sh
if [ $# -eq 0 ];then
  exec bin/yazproxy -c $CONF @:$PORT -u yaz
else
  exec bin/yazproxy $@
fi