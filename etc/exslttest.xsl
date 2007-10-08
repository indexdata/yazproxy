<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0" 
                xmlns:date="http://exslt.org/dates-and-times" 
                extension-element-prefixes="date">
  
  <xsl:output media-type="text/xml" 
              indent="yes" method="xml" encoding="UTF-8" />

  <xsl:template match="/">
    <daterec>
      <xsl:copy-of select="."/>
      <date>
	<xsl:value-of select="date:date()"/> 
      </date>
    </daterec>
  </xsl:template>
</xsl:stylesheet>
