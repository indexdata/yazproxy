## $Id: Makefile.am,v 1.18 2007-07-10 09:42:09 adam Exp $
SUBDIRS = common

XMLFILES = \
 introduction.xml \
 installation.xml \
 reference.xml \
 using.xml \
 yaz-proxy-ref.xml \
 yaz-proxy-man.xml \
 license.xml \
 yazproxy.xml
 
TOP = $(srcdir)/yazproxy.xml

MANFILES = yazproxy.8

HTMLFILES = index.html

doc_DATA = $(HTMLFILES)

man_MANS = $(MANFILES)

EXTRA_DIST = $(XMLFILES) $(doc_DATA) $(man_MANS) entities.ent local.ent

$(HTMLFILES): $(XMLFILES)
	rm -f *.html
	$(HTML_COMPILE) $(TOP)

yazproxy.8: yaz-proxy-man.xml yaz-proxy-ref.xml
	$(MAN_COMPILE) $(srcdir)/yaz-proxy-man.xml

index.tkl: $(XMLFILES)
	$(TKL_COMPILE) $(TOP)

yazproxy.pdf: $(XMLFILES)
	if test ! -f common/id.png ; then cp $(srcdir)/common/id.png common; fi
	jade -E14 -D $(srcdir) -d common/print.dsl -t tex $(srcdir)/common/xml.dcl $(TOP)
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1

clean-data-hook:
	rm -f [0-9]* *.bak

dist-hook:
	if test -f index.html; then d=.; else d="$(srcdir)"; fi; \
	for p in $$d/*.html; do \
		cp $$p $(distdir); \
	done

install-data-hook:
	if test -f index.html; then d=.; else d="$(srcdir)"; fi; \
	for p in $$d/*.html; do \
		$(docDATA_INSTALL) $$p $(DESTDIR)$(docdir); \
	done

uninstall-hook:
	rm -r $(DESTDIR)$(docdir)
