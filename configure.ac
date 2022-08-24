dnl This file is part of YAZ proxy
dnl See the file LICENSE for details.
AC_PREREQ([2.69])
AC_INIT([yazproxy],[m4_esyscmd([. ./IDMETA; printf $VERSION])],[info@indexdata.com])
AC_CONFIG_SRCDIR(configure.ac)
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([1.9])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX

LT_INIT

YAZPP_INIT([threads],[1.1.4])
if test -z "$YAZPPLIB"; then
	AC_MSG_ERROR([YAZ++ development libraries missing])
fi
YAZ_DOC
USEMARCON_INIT

AC_CHECK_FUNCS([setrlimit getrlimit gettimeofday])
AC_CHECK_HEADERS([sys/resource.h sys/stat.h sys/time.h sys/types.h unistd.h])
AC_CHECK_LIB([dl],[dlopen])
dnl
AC_CONFIG_FILES([
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
AC_OUTPUT
