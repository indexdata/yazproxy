## $Id: Makefile.am,v 1.9 2006-04-20 12:05:54 adam Exp $
docdir=$(datadir)/doc/@PACKAGE@

SUBDIRS = common

XMLFILES = \
 introduction.xml \
 installation.xml \
 reference.xml \
 using.xml \
 yaz-proxy-ref.xml \
 yaz-proxy-man.xml \
 license.xml \
 yazproxy.xml.in
 
TOP=yazproxy.xml
MANFILES=yazproxy.8
HTMLFILES =  \
 installation.html \
 introduction.html \
 license.html \
 other-optimizations.html \
 otherinfo-encoding.html \
 proxy-config-file.html \
 proxy-keepalive.html \
 proxy-reference.html \
 proxy-target.html \
 proxy-usage.html \
 query-cache.html \
 query-validation.html \
 record-cache.html \
 record-validation.html \
 support.html \
 using.html \
 windows.html \
 yazproxy-man.html \
 yazproxy-schema.html \
 yazproxy.html

doc_DATA = $(HTMLFILES) yazproxy.pdf

man_MANS = $(MANFILES)

EXTRA_DIST = $(XMLFILES) $(doc_DATA) $(man_MANS)

$(HTMLFILES): $(XMLFILES)
	jade -E14 -D $(srcdir) -d common/html.dsl -t sgml $(srcdir)/common/xml.dcl $(TOP)

yazproxy.8: yaz-proxy-man.xml yaz-proxy-ref.xml
	docbook2man $(srcdir)/yaz-proxy-man.xml

yazproxy.pdf: $(XMLFILES)
	if test ! -f common/id.png ; then cp $(srcdir)/common/id.png common; fi
	jade -E14 -D $(srcdir) -d common/print.dsl -t tex $(srcdir)/common/xml.dcl $(TOP)
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1

index.tkl: $(XMLFILES) common/tkl.xsl
	xsltproc common/tkl.xsl $(TOP)

clean-data-hook:
	rm -f [0-9]* *.bak

dist-hook:
	for f in $(srcdir)/*.html; do \
		found=0; \
		b=`basename $$f`; \
		for h in $(HTMLFILES); do \
			if test "$$h" = "$$b"; then \
				found=1; \
			fi \
		done; \
		if test "$$found" = "0"; then \
			echo "$$h not found in HTMLFILES"; \
			exit 1; \
		fi \
	done

