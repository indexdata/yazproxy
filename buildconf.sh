#!/bin/sh
# $Id: buildconf.sh,v 1.4 2004-08-16 12:39:44 adam Exp $
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
