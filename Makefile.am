AUTOMAKE_OPTIONS = foreign

SUBDIRS = src include etc doc 

EXTRA_DIST= README LICENSE yazpp.m4 buildconf.sh

##	mkdir $(distdir)/win
##	cp $(srcdir)/win/makefile $(distdir)/win/

dist-hook:
	mkdir $(distdir)/debian
	cp $(srcdir)/debian/control $(distdir)/debian
	cp $(srcdir)/debian/changelog $(distdir)/debian
	cp $(srcdir)/debian/rules $(distdir)/debian
	cp $(srcdir)/debian/postinst $(distdir)/debian
	cp $(srcdir)/debian/compat $(distdir)/debian
	cp $(srcdir)/debian/*.install $(distdir)/debian
