AUTOMAKE_OPTIONS = foreign

SUBDIRS = src include etc doc 

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST= README LICENSE m4/yazpp.m4 m4/yaz.m4 m4/usemarcon.m4 buildconf.sh

dist-hook:
	if test -x /usr/bin/git -a -d .git; then git log >ChangeLog ; cp ChangeLog $(distdir); fi
	mkdir $(distdir)/win
	cp $(srcdir)/win/makefile $(distdir)/win/
	mkdir $(distdir)/debian
	cp $(srcdir)/debian/control $(distdir)/debian
	cp $(srcdir)/debian/changelog $(distdir)/debian
	cp $(srcdir)/debian/copyright $(distdir)/debian
	cp $(srcdir)/debian/rules $(distdir)/debian
	cp $(srcdir)/debian/*.install $(distdir)/debian
	cp $(srcdir)/debian/*.manpages $(distdir)/debian
