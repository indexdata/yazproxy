#!/bin/sh
if [ $# -eq 0 ];then
  exec bin/yazproxy -c $CONF @:$PORT
else
  exec bin/yazproxy $@
fi