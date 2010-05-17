AM_CXXFLAGS = -I$(srcdir)/../include $(YAZPPINC) $(USEMARCONINC)

lib_LTLIBRARIES = libyazproxy.la
libyazproxy_la_LDFLAGS=-version-info 2:0:0

libyazproxy_la_SOURCES= yaz-proxy.cpp yaz-proxy-config.cpp yaz-bw.cpp \
 proxyp.h yaz-usemarcon.cpp charset-converter.cpp msg-thread.cpp msg-thread.h \
 modules.cpp limit-connect.cpp

bin_PROGRAMS = yazproxy
check_PROGRAMS = cdetails
noinst_PROGRAMS = tstthreads t-server

TESTS=$(check_PROGRAMS)

yazproxy_SOURCES=yaz-proxy-main.cpp
cdetails_SOURCES=cdetails.cpp
tstthreads_SOURCES=tstthreads.cpp
t_server_SOURCES=t-server.cpp

libyazproxy_la_LIBADD = $(YAZPPLALIB)

LDADD=libyazproxy.la $(USEMARCONLALIB)

# Modules
mod_proxy_sample_la_SOURCES = mod_sample.cpp
mod_proxy_sample_la_LDFLAGS = -rpath $(pkglibdir) -module -avoid-version

mod_proxy_helsinki_la_SOURCES = mod_helsinki.cpp
mod_proxy_helsinki_la_LDFLAGS = -rpath $(pkglibdir) -module -avoid-version

pkglib_LTLIBRARIES = mod_proxy_sample.la mod_proxy_helsinki.la

