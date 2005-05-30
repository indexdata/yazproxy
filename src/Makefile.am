## $Id: Makefile.am,v 1.8 2005-05-30 20:09:21 adam Exp $

AM_CXXFLAGS = $(YAZPPINC) -I$(srcdir)/../include $(XSLT_CFLAGS) $(USEMARCONINC)

lib_LTLIBRARIES = libyazproxy.la
libyazproxy_la_LDFLAGS=-version-info 1:0:0

libyazproxy_la_SOURCES= yaz-proxy.cpp yaz-proxy-config.cpp yaz-bw.cpp \
 proxyp.h yaz-usemarcon.cpp charset-converter.cpp msg-thread.cpp msg-thread.h \
 modules.cpp

bin_PROGRAMS = yazproxy
check_PROGRAMS = cdetails
noinst_PROGRAMS = tstthreads

TESTS=$(check_PROGRAMS)

yazproxy_SOURCES=yaz-proxy-main.cpp
cdetails_SOURCES=cdetails.cpp
tstthreads_SOURCES=tstthreads.cpp

LDADD=libyazproxy.la $(YAZPPLALIB) $(XSLT_LIBS) $(USEMARCONLALIB)
libyazproxy_la_LIBADD = $(XSLT_LIBS)

# Modules
mod_proxy_sample_la_SOURCES = mod_sample.cpp
mod_proxy_sample_la_LDFLAGS = -rpath $(pkglibdir) -module -avoid-version

pkglib_LTLIBRARIES = mod_proxy_sample.la
