AUTOMAKE_OPTIONS = foreign

SUBDIRS = src include etc doc 

ACLOCAL_AMFLAGS = -I m4

SPEC_FILE=$(PACKAGE).spec
EXTRA_DIST= $(SPEC_FILE) README LICENSE NEWS m4/id-config.sh \
	m4/yazpp.m4 m4/yaz.m4 m4/usemarcon.m4 buildconf.sh

dist-hook:
	if test -x /usr/bin/git -a -d .git; then git log >ChangeLog ; cp ChangeLog $(distdir); fi
	mkdir $(distdir)/win
	cp $(srcdir)/win/makefile $(distdir)/win/

