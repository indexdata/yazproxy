## $Id: Makefile.am,v 1.7 2004-04-22 18:47:02 adam Exp $
docdir=$(datadir)/doc/@PACKAGE@

SUPPORTFILES = \
 yazhtml.dsl.in \
 yazphp.dsl.in \
 yazprint.dsl.in \
 tkl.xsl.in \
 xml.dcl
XMLFILES = \
 introduction.xml \
 installation.xml \
 reference.xml \
 using.xml \
 yaz-proxy-ref.xml \
 yaz-proxy-man.sgml \
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

doc_DATA = $(HTMLFILES) yazproxy.pdf id.png yaz.css

man_MANS = $(MANFILES)

EXTRA_DIST = $(SUPPORTFILES) $(XMLFILES) $(doc_DATA) $(man_MANS)

$(HTMLFILES): $(XMLFILES)
	jade -E14 -D $(srcdir) -d yazhtml.dsl -t sgml $(srcdir)/xml.dcl $(TOP)

yazproxy.8: yaz-proxy-man.sgml yaz-proxy-ref.xml
	docbook2man $(srcdir)/yaz-proxy-man.sgml

yazproxy.php: $(XMLFILES)
	jade -E14 -D $(srcdir) -d yazphp.dsl -t sgml $(srcdir)/xml.dcl $(TOP)

yazproxy.pdf: $(XMLFILES)
	if test ! -f id.png ; then ln -s $(srcdir)/id.png .; fi
	jade -E14 -D $(srcdir) -d yazprint.dsl -t tex $(srcdir)/xml.dcl $(TOP)
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1
	pdfjadetex yazproxy.tex >pdfjadetex.log 2>&1

index.tkl: $(XMLFILES) tkl.xsl
	xsltproc tkl.xsl $(TOP)

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

