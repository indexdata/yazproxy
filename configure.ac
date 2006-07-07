dnl yazproxy, Index Data 1994-2006
dnl See the file LICENSE for details.
dnl $Id: configure.ac,v 1.14 2006-07-07 12:17:00 adam Exp $
AC_PREREQ(2.59)
AC_INIT([yazproxy],[1.2.1.1],[adam@indexdata.dk])
AC_CONFIG_SRCDIR(configure.ac)
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([1.8])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_HEADER_STDC
AM_PROG_LIBTOOL

YAZPP_INIT(threads,1.0.1)
if test -z "$YAZPPLIB"; then
	AC_MSG_ERROR([YAZ++ development libraries missing])
fi
YAZ_DOC
USEMARCON_INIT

AC_CHECK_FUNCS(setrlimit getrlimit gettimeofday)
AC_CHECK_HEADERS(pwd.h sys/resource.h sys/stat.h sys/time.h sys/types.h sys/wait.h unistd.h)
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
