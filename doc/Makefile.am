## $Id: Makefile.am,v 1.1.1.1 2004-04-11 11:36:53 adam Exp $
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
 zoom.xml \
 proxy.xml \
 api.xml \
 yaz-proxy-ref.xml \
 yaz-proxy-man.sgml \
 license.xml \
 yaz++.xml.in
 
TOP=yaz++.xml
MANFILES=yaz-proxy.8
HTMLFILES = \
 api.html \
 implementations.html \
 installation.html \
 introduction.html \
 license.html \
 other-optimizations.html \
 otherinfo-encoding.html \
 proxy-config-file.html \
 proxy-keepalive.html \
 proxy-target.html \
 proxy-usage.html \
 proxy.html \
 query-cache.html \
 query-validation.html \
 record-cache.html \
 record-validation.html \
 windows.html \
 yaz-proxy.html \
 yaz.license.html \
 yazpp.html \
 zoom-connection.html \
 zoom-exception.html \
 zoom-query.html \
 zoom-record.html \
 zoom-resultset.html \
 zoom.html

doc_DATA = $(HTMLFILES) yaz++.pdf id.png yaz.css

man_MANS = $(MANFILES)

EXTRA_DIST = $(SUPPORTFILES) $(XMLFILES) $(doc_DATA) $(man_MANS)

$(HTMLFILES): $(XMLFILES)
	jade -E14 -D $(srcdir) -d yazhtml.dsl -t sgml $(srcdir)/xml.dcl $(TOP)

yaz-proxy.8: yaz-proxy-man.sgml yaz-proxy-ref.xml
	docbook2man $(srcdir)/yaz-proxy-man.sgml

yazpp.php: $(XMLFILES)
	jade -E14 -D $(srcdir) -d yazphp.dsl -t sgml $(srcdir)/xml.dcl $(TOP)

yaz++.pdf: $(XMLFILES)
	if test ! -f id.png ; then ln -s $(srcdir)/id.png .; fi
	jade -E14 -D $(srcdir) -d yazprint.dsl -t tex $(srcdir)/xml.dcl $(TOP)
	pdfjadetex yaz++.tex >pdfjadetex.log 2>&1
	pdfjadetex yaz++.tex >pdfjadetex.log 2>&1
	pdfjadetex yaz++.tex >pdfjadetex.log 2>&1

index.tkl: $(XMLFILES) tkl.xsl
	xsltproc tkl.xsl $(TOP)

clean-data-hook:
	rm -f [0-9]* *.bak

