dnl This file is part of YAZ proxy
dnl See the file LICENSE for details.
AC_PREREQ(2.60)
AC_INIT([yazproxy],[1.3.3.2],[adam@indexdata.dk])
AC_CONFIG_SRCDIR(configure.ac)
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([1.9])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_HEADER_STDC
AM_PROG_LIBTOOL

YAZPP_INIT([threads],[1.1.0])
if test -z "$YAZPPLIB"; then
	AC_MSG_ERROR([YAZ++ development libraries missing])
fi
YAZ_DOC
USEMARCON_INIT

AC_CHECK_FUNCS(setrlimit getrlimit gettimeofday)
AC_CHECK_HEADERS(sys/resource.h sys/stat.h sys/time.h sys/types.h unistd.h)
AC_CHECK_LIB(dl,dlopen)
dnl
AC_SUBST(YAZPROXY_SRC_ROOT)
AC_SUBST(YAZPROXY_BUILD_ROOT)
YAZPROXY_SRC_ROOT=`cd ${srcdir}; pwd`
YAZPROXY_BUILD_ROOT=`pwd`
AC_OUTPUT([
	Makefile
	src/Makefile
	include/Makefile
	include/yazproxy/Makefile
	doc/Makefile
	doc/local.ent
	doc/common/Makefile
	doc/common/print.dsl
	etc/Makefile
])
