## $Id: Makefile.am,v 1.4 2004-12-03 15:50:53 adam Exp $

AM_CXXFLAGS = $(YAZPPINC) -I$(srcdir)/../include $(XSLT_CFLAGS) $(USEMARCONINC)

lib_LTLIBRARIES = libyazproxy.la
libyazproxy_la_LDFLAGS=-version-info 1:0:0

libyazproxy_la_SOURCES= yaz-proxy.cpp yaz-proxy-config.cpp yaz-bw.cpp \
 proxyp.h yaz-usemarcon.cpp

bin_PROGRAMS = yazproxy
check_PROGRAMS = cdetails

TESTS=$(check_PROGRAMS)

yazproxy_SOURCES=yaz-proxy-main.cpp
cdetails_SOURCES=cdetails.cpp

LDADD=libyazproxy.la $(YAZPPLALIB) $(XSLT_LIBS) $(USEMARCONLALIB)
libyazproxy_la_LIBADD = $(XSLT_LIBS)
