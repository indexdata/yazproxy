## $Id: Makefile.am,v 1.2 2004-04-11 11:58:35 adam Exp $

AM_CXXFLAGS = $(YAZPPINC) -I$(srcdir)/../include $(XSLT_CFLAGS)

lib_LTLIBRARIES = libyazproxy.la
libyazproxy_la_LDFLAGS=-version-info 1:0:0

libyazproxy_la_SOURCES= yaz-proxy.cpp yaz-proxy-config.cpp yaz-bw.cpp

bin_PROGRAMS = yazproxy

yazproxy_SOURCES=yaz-proxy-main.cpp

LDADD=libyazproxy.la $(YAZPPLALIB) $(XSLT_LIBS)
libyazproxy_la_LIBADD = $(XSLT_LIBS)
