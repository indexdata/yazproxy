## $Id: Makefile.am,v 1.1 2004-04-11 11:36:46 adam Exp $

AM_CXXFLAGS = $(YAZINC) -I$(srcdir)/../include $(XSLT_CFLAGS)

lib_LTLIBRARIES = libyazproxy.la
libyazproxy_la_LDFLAGS=-version-info 1:0:0

libyazproxy_la_SOURCES= yaz-proxy.cpp yaz-proxy-config.cpp yaz-bw.cpp

bin_PROGRAMS = yaz-proxy

yaz_proxy_SOURCES=yaz-proxy-main.cpp

LDADD=libyazproxy.la ../src/libyazcpp.la $(YAZLALIB) $(XSLT_LIBS)
libyazproxy_la_LIBADD = $(XSLT_LIBS)
