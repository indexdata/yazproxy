#!/bin/sh
# $Id: buildconf.sh,v 1.5 2005-02-08 14:06:51 adam Exp $
set -x
dir=`aclocal --print-ac-dir`
aclocal -I .
libtoolize --force 
automake -a 
automake -a 
autoconf
if [ -f config.cache ]; then
	rm config.cache
fi
