#!/bin/sh
# $Id: buildconf.sh,v 1.2 2004-04-11 14:25:50 adam Exp $
set -x
dir=`aclocal --print-ac-dir`
if [ -f $dir/yazpp.m4 ]; then
	aclocal
else
	aclocal -I . 
fi
libtoolize --force 
automake -a 
automake -a 
autoconf
if [ -f config.cache ]; then
	rm config.cache
fi
