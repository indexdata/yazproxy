dnl yazproxy, Index Data 1994-2006
dnl See the file LICENSE for details.
dnl $Id: configure.ac,v 1.1 2006-03-28 20:00:15 adam Exp $
AC_PREREQ(2.59)
AC_INIT([yazproxy],[1.1.0],[adam@indexdata.dk])
AC_CONFIG_SRCDIR(configure.ac)
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([1.8])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_HEADER_STDC
AM_DISABLE_SHARED
AM_PROG_LIBTOOL

YAZPP_INIT(threads,1.0)
if test -z "$YAZPPLIB"; then
	AC_MSG_ERROR([YAZ++ development libraries missing])
fi
YAZ_DOC
USEMARCON_INIT

AC_CHECK_FUNCS(setrlimit getrlimit gettimeofday)
AC_CHECK_HEADERS(pwd.h sys/resource.h sys/stat.h sys/time.h sys/types.h sys/wait.h unistd.h)
AC_CHECK_LIB(dl,dlopen)
dnl
dnl ----- libXSLT
AC_SUBST(XSLT_LIBS)
AC_SUBST(XSLT_CFLAGS)
xsltdir=default
AC_ARG_WITH(xslt,[[  --with-xslt[=PREFIX]    use libxslt in PREFIX]],xsltdir=$withval)
if test "$xsltdir" = "yes" -o "$xsltdir" = "default"; then
	for d in /usr /usr/local; do
		if test -x $d/bin/xslt-config; then
			xsltdir=$d
		fi
	done
fi
if test "$xsltdir" != "no"; then
	AC_MSG_CHECKING(for libXSLT)
	if test -x $xsltdir/bin/xslt-config; then
		XSLT_LIBS=`$xsltdir/bin/xslt-config --libs`
		XSLT_CFLAGS=`$xsltdir/bin/xslt-config --cflags`
		XSLT_VER=`$xsltdir/bin/xslt-config --version`
		AC_MSG_RESULT($XSLT_VER)
		AC_DEFINE(HAVE_XSLT)
	else
		AC_MSG_RESULT(Not found)
                if test "$xsltdir" = "default"; then
                        AC_MSG_WARN([Libxslt development libraries not found.])
                else
                        AC_MSG_ERROR([libxslt development libraries not found.])                fi
	fi
fi

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
	doc/yazproxy.xml
	doc/yazprint.dsl doc/yazphp.dsl doc/yazhtml.dsl
        doc/tkl.xsl
	etc/Makefile
])